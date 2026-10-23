//! Public-repository hygiene: nothing tracked here may point at material that lives outside this
//! repository. Design notes, task lists and process documents are kept elsewhere; a reference to
//! one would be a dangling link for every reader, so source, tests and the README stay
//! self-contained.
//!
//! The needles are assembled at run time so that this file does not contain them itself.

use std::fs;
use std::path::{Path, PathBuf};

/// Strings that name documents or repositories a public reader cannot open.
fn needles() -> Vec<String> {
    vec![
        ["technical", ".md"].concat(),
        ["architecture", ".md"].concat(),
        ["product-", "requirements"].concat(),
        ["eero-mcp", "-context"].concat(),
        ["active", "-context"].concat(),
        ["tasks", "-plan"].concat(),
        [".claude", "/"].concat(),
        ["CLAUDE", ".md"].concat(),
        [".cursor", "/"].concat(),
    ]
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn is_text(path: &Path) -> bool {
    path.extension().is_some_and(|ext| {
        ["rs", "md", "toml", "json", "yml", "yaml", "txt"]
            .iter()
            .any(|known| ext == *known)
    })
}

#[test]
fn tracked_files_do_not_reference_private_material() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests", ".github"] {
        if root.join(dir).is_dir() {
            collect(&root.join(dir), &mut files);
        }
    }
    for name in ["README.md", "Cargo.toml", "NOTICE", "deny.toml"] {
        if root.join(name).is_file() {
            files.push(root.join(name));
        }
    }
    assert!(files.len() > 20, "the scan found the tree: {}", files.len());

    let needles = needles();
    let mut found = Vec::new();
    for file in files
        .iter()
        .filter(|file| is_text(file) || file.extension().is_none())
    {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            for needle in &needles {
                if line.contains(needle.as_str()) {
                    found.push(format!(
                        "{}:{}: mentions `{needle}`",
                        file.strip_prefix(&root).unwrap_or(file).display(),
                        index + 1
                    ));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "the public repository must be self-contained:\n{}",
        found.join("\n")
    );
}

/// Every mock eero cloud must come from `common::mock_cloud()`, which mounts the write tripwire
/// (any POST, PUT, PATCH or DELETE fails the test). A test file that starts its own server could
/// forget it, so only the harness may.
#[test]
fn only_the_harness_starts_a_mock_server() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = Vec::new();
    collect(&root, &mut files);
    let needle = ["MockServer", "::start"].concat();
    let mut offenders = Vec::new();
    for file in files
        .iter()
        .filter(|file| file.extension().is_some_and(|ext| ext == "rs"))
    {
        let relative = file.strip_prefix(&root).unwrap_or(file);
        if relative == Path::new("common/mod.rs") {
            continue;
        }
        if fs::read_to_string(file).is_ok_and(|text| text.contains(&needle)) {
            offenders.push(relative.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "start mock servers with common::mock_cloud(), which mounts the write tripwire: {offenders:?}"
    );
}
