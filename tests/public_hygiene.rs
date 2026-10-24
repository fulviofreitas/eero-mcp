//! Public-repository hygiene: nothing tracked here may point at material that lives outside this
//! repository. Design notes, task lists and process documents are kept elsewhere; a reference to
//! one would be a dangling link for every reader, so source, tests and the README stay
//! self-contained.
//!
//! The needles are assembled at run time so that this file does not contain them itself.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Directories of local tooling and build output that are not part of the published tree.
const SKIPPED_DIRS: &[&str] = &["target", ".git", "graphify-out", ".claude", ".cursor"];

/// Local tooling files that are not part of the published tree (assembled at run time, like the
/// needles, so this file does not contain the name).
fn skipped_files() -> Vec<String> {
    vec![["CLAUDE", ".md"].concat()]
}

/// Every file under `dir` except the local tooling and build output, whatever its extension.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name.as_str()) {
                walk(&path, out);
            }
        } else if !skipped_files().contains(&name) {
            out.push(path);
        }
    }
}

/// The git-tracked files, or `None` when this is not a git checkout (a source tarball, say).
fn tracked_files(root: &Path) -> Option<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let files: Vec<PathBuf> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .filter_map(|name| std::str::from_utf8(name).ok())
        .map(|name| root.join(name))
        .collect();
    (!files.is_empty()).then_some(files)
}

/// Every file that ships with the repository: the tracked files, else the whole crate tree.
fn shipped_files(root: &Path) -> Vec<PathBuf> {
    tracked_files(root).unwrap_or_else(|| {
        let mut files = Vec::new();
        walk(root, &mut files);
        files
    })
}

#[test]
fn tracked_files_do_not_reference_private_material() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = shipped_files(&root);
    assert!(files.len() > 20, "the scan found the tree: {}", files.len());
    // Files the old extension filter skipped must now be in the scan.
    for required in [
        ".github/renovate.json5",
        "CITATION.cff",
        ".gitignore",
        "VERSION",
    ] {
        assert!(
            files.iter().any(|file| file.ends_with(required)),
            "{required} is scanned"
        );
    }

    let needles = needles();
    let mut found = Vec::new();
    for file in &files {
        // A file that cannot be read as UTF-8 text (or no longer exists) has nothing to scan.
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
