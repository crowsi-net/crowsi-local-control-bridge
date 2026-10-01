use std::{fs, path::Path};

#[test]
fn unsigned_revocation_snapshot_surface_cannot_return() {
    for path in production_sources() {
        let source = fs::read_to_string(&path).expect("Rust source");
        for forbidden in [
            "apply_trusted_revocation_snapshot",
            "IdentityRevocationSnapshotV1",
            "identity/revocation-snapshot/v1",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} contains forbidden unsigned snapshot surface {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn production_sources_stay_within_the_reviewable_line_limit() {
    for path in production_sources() {
        let source = fs::read_to_string(&path).expect("Rust source");
        let lines = noncomment_lines(&source);
        assert!(
            lines <= 149,
            "{} has {lines} non-comment lines",
            path.display()
        );
    }
}

fn production_sources() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    collect(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut paths,
    );
    paths
}

fn collect(directory: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "tests") {
                collect(&path, paths);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_name().is_some_and(|name| name != "tests.rs")
        {
            paths.push(path);
        }
    }
}

fn noncomment_lines(source: &str) -> usize {
    let mut in_block = false;
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if in_block {
                if trimmed.contains("*/") {
                    in_block = false;
                }
                return false;
            }
            if trimmed.starts_with("/*") {
                in_block = !trimmed.contains("*/");
                return false;
            }
            !trimmed.is_empty() && !trimmed.starts_with("//")
        })
        .count()
}
