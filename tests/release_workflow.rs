//! The release workflow publishes the dependency graph it tested.
//!
//! `release.yml` ran `cargo test --locked` and `cargo clippy --locked`
//! and then `cargo publish` without it, so the crate that reached
//! crates.io could be built from a resolution nobody had tested: any
//! dependency with a newer semver-compatible release since `Cargo.lock`
//! was last updated was picked up silently (#87).
//!
//! The same workflow cloned the `am-fs-core` sibling at a tag written
//! out twice, once per job, so a bump made in one place gave the two
//! jobs different siblings — the publish job building against a crate
//! the test job never saw.
//!
//! The workflow is PARSED rather than scanned: a `run:` is a block
//! scalar or a plain one at the author's discretion, and a text match
//! over the file would also match comments and step names.

use saphyr::{LoadableYamlNode, Yaml};
use std::path::Path;

const WORKFLOW: &str = ".github/workflows/release.yml";

/// Cargo subcommands that resolve the dependency graph.
const RESOLVING: &[&str] = &[
    "build", "check", "clippy", "doc", "package", "publish", "run", "test",
];

fn load(yaml: &str) -> Yaml<'static> {
    let mut docs = Yaml::load_from_str(yaml).expect("the workflow parses as YAML");
    assert_eq!(docs.len(), 1, "one YAML document");
    docs.remove(0)
}

/// Every step's `run:` script, with its job's name.
fn run_scripts(doc: &Yaml) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let jobs = doc
        .as_mapping_get("jobs")
        .and_then(Yaml::as_mapping)
        .expect("the workflow has jobs");
    for (name, job) in jobs {
        let name = name.as_str().unwrap_or("?").to_owned();
        let Some(steps) = job.as_mapping_get("steps").and_then(Yaml::as_sequence) else {
            continue;
        };
        for step in steps {
            if let Some(run) = step.as_mapping_get("run").and_then(Yaml::as_str) {
                out.push((name.clone(), run.to_owned()));
            }
        }
    }
    out
}

/// The cargo invocations in a script, as word lists starting at the
/// subcommand, each cut at `--` so an argument meant for the program
/// being run is not read as cargo's.
fn cargo_invocations(script: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    // A backslash-newline continues the line; `;`, `&&`, `||`, `|`, `&`
    // and a subshell's parentheses all start another command.
    let joined = script.replace("\\\n", " ");
    for command in joined.split(['\n', ';', '|', '&', '(', ')']) {
        let words: Vec<&str> = command.split_whitespace().collect();
        // The command word, past `env` and `VAR=value` prefixes. A
        // `cargo` anywhere else is an argument (`echo cargo publish`).
        let is_prefix = |w: &str| w == "env" || (w.contains('=') && !w.starts_with('-'));
        let Some(at) = words.iter().position(|w| !is_prefix(w)) else {
            continue;
        };
        if words[at] != "cargo" && !words[at].ends_with("/cargo") {
            continue;
        }
        let rest: Vec<String> = words[at + 1..]
            .iter()
            .skip_while(|w| w.starts_with('+'))
            .take_while(|w| **w != "--")
            .map(|w| (*w).to_owned())
            .collect();
        if !rest.is_empty() {
            out.push(rest);
        }
    }
    out
}

/// Every resolving cargo command in `yaml` that does not pass `--locked`.
fn unlocked(yaml: &str) -> Vec<String> {
    let doc = load(yaml);
    let mut seen = 0;
    let mut missing = Vec::new();
    for (job, script) in run_scripts(&doc) {
        for words in cargo_invocations(&script) {
            if !RESOLVING.contains(&words[0].as_str()) {
                continue;
            }
            seen += 1;
            if !words.iter().any(|w| w == "--locked") {
                missing.push(format!("{job}: cargo {}", words.join(" ")));
            }
        }
    }
    // An empty answer from a reader that found no cargo command at all
    // is not a clean bill of health.
    assert!(seen > 0, "no resolving cargo command found in the workflow");
    missing
}

/// The `--branch` of every step that clones `rust-fs-core`.
fn fs_core_clone_refs(yaml: &str) -> Vec<String> {
    let doc = load(yaml);
    let mut refs = Vec::new();
    for (_, script) in run_scripts(&doc) {
        for line in script.lines().filter(|l| l.contains("rust-fs-core")) {
            let words: Vec<&str> = line.split_whitespace().collect();
            if !words.contains(&"clone") {
                continue;
            }
            let branch = words
                .iter()
                .position(|w| *w == "--branch")
                .and_then(|i| words.get(i + 1))
                .unwrap_or_else(|| panic!("a rust-fs-core clone with no --branch: {line}"));
            refs.push((*branch).to_owned());
        }
    }
    refs
}

/// Every job or step that sets `var` in its own `env:`, shadowing the
/// workflow-level value.
fn env_overrides(doc: &Yaml, var: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(jobs) = doc.as_mapping_get("jobs").and_then(Yaml::as_mapping) else {
        return out;
    };
    for (name, job) in jobs {
        let name = name.as_str().unwrap_or("?");
        if job
            .as_mapping_get("env")
            .and_then(|e| e.as_mapping_get(var))
            .is_some()
        {
            out.push(format!("job {name}"));
        }
        let steps = job.as_mapping_get("steps").and_then(Yaml::as_sequence);
        for (i, step) in steps.into_iter().flatten().enumerate() {
            if step
                .as_mapping_get("env")
                .and_then(|e| e.as_mapping_get(var))
                .is_some()
            {
                out.push(format!("job {name} step {i}"));
            }
        }
    }
    out
}

fn workflow() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(WORKFLOW);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {WORKFLOW}: {e}"))
}

#[test]
fn every_cargo_command_in_the_release_workflow_is_locked() {
    let missing = unlocked(&workflow());
    assert!(
        missing.is_empty(),
        "{WORKFLOW} resolves dependencies without --locked, so what it runs or \
         publishes can differ from what Cargo.lock describes: {missing:?}"
    );
}

#[test]
fn the_fs_core_sibling_tag_is_stated_once() {
    let yaml = workflow();
    let refs = fs_core_clone_refs(&yaml);
    assert!(
        refs.len() >= 2,
        "expected the test and publish jobs to clone rust-fs-core, found {refs:?}"
    );
    // The shell reads the workflow-level `env:` directly.
    let shared = "\"$FS_CORE_REF\"";
    assert!(
        refs.iter().all(|r| r == shared),
        "every rust-fs-core clone must use {shared} so a bump cannot give the jobs \
         different siblings; found {refs:?}"
    );
    let overrides = env_overrides(&load(&yaml), "FS_CORE_REF");
    assert!(
        overrides.is_empty(),
        "FS_CORE_REF is set again below the workflow level, so a clone can resolve a \
         different tag than the one declared once: {overrides:?}"
    );
    let declared = load(&yaml)
        .as_mapping_get("env")
        .and_then(|e| e.as_mapping_get("FS_CORE_REF"))
        .and_then(Yaml::as_str)
        .map(str::to_owned);
    assert!(
        declared.as_deref().is_some_and(|t| t.starts_with('v')),
        "the workflow-level env must declare FS_CORE_REF as a tag, found {declared:?}"
    );
}

/// The readers above answer for the inputs they are meant to catch, and
/// not for the ones they are not.
#[test]
fn the_readers_discriminate() {
    let yaml = "jobs:\n  a:\n    steps:\n      - run: cargo test --locked --all-targets\n      - name: publish\n        run: |\n          echo cargo publish is next\n          cargo publish\n      - run: cargo run --locked -- --locked\n      - run: cargo +1.95.0 build\n      - run: cargo fmt --check\n";
    let missing = unlocked(yaml);
    assert_eq!(
        missing,
        vec!["a: cargo publish", "a: cargo build"],
        "`echo cargo publish` is not a cargo command, fmt does not resolve, and a \
         --locked after -- belongs to the program; got {missing:?}"
    );
    let missing = unlocked("jobs:\n  a:\n    steps:\n      - run: cargo run -- --locked\n");
    assert_eq!(missing, vec!["a: cargo run"]);

    // Commands a line-and-`&&` split would miss.
    for (script, want) in [
        ("cargo \\\n  publish", "a: cargo publish"),
        ("git clean -xfd || cargo publish", "a: cargo publish"),
        ("true | cargo package", "a: cargo package"),
        ("(cd x && cargo build)", "a: cargo build"),
    ] {
        let yaml = format!("jobs:\n  a:\n    steps:\n      - run: {script:?}\n");
        assert_eq!(unlocked(&yaml), vec![want], "{script:?}");
    }

    let shadowed = "env:\n  FS_CORE_REF: v1\njobs:\n  a:\n    env:\n      FS_CORE_REF: v2\n    steps:\n      - env:\n          FS_CORE_REF: v3\n        run: echo\n";
    assert_eq!(
        env_overrides(&load(shadowed), "FS_CORE_REF"),
        vec!["job a", "job a step 0"]
    );

    let clones = "jobs:\n  a:\n    steps:\n      - run: git clone --depth 1 --branch v0.2.10 https://github.com/antimatter-studios/rust-fs-core.git ../rust-fs-core\n";
    assert_eq!(fs_core_clone_refs(clones), vec!["v0.2.10"]);
}
