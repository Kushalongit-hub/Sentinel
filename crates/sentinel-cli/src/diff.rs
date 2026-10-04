use crate::ScanArgs;
use anyhow::Result;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};
pub fn diff() -> Result<i32> {
    diff_with_options(ScanArgs::default(), false, false, false)
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !out.status.success() {
        anyhow::bail!("git failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(out.stdout)
}
fn paths(bytes: Vec<u8>) -> Result<Vec<PathBuf>> {
    Ok(String::from_utf8(bytes)?
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect())
}
pub fn diff_with_options(
    args: ScanArgs,
    staged: bool,
    unstaged: bool,
    tracked_only: bool,
) -> Result<i32> {
    let root = String::from_utf8(git(Path::new("."), &["rev-parse", "--show-toplevel"])?)?;
    let root = PathBuf::from(root.trim_end_matches(['\r', '\n'])).canonicalize()?;
    let mut changed = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    if !unstaged {
        changed.extend(paths(git(
            &root,
            &["diff", "--cached", "--name-only", "-z"],
        )?)?);
        deleted.extend(paths(git(
            &root,
            &["diff", "--cached", "--name-only", "--diff-filter=D", "-z"],
        )?)?);
    }
    if !staged {
        changed.extend(paths(git(&root, &["diff", "--name-only", "-z"])?)?);
        deleted.extend(paths(git(
            &root,
            &["diff", "--name-only", "--diff-filter=D", "-z"],
        )?)?);
    }
    if !tracked_only && !staged && !unstaged {
        changed.extend(paths(git(
            &root,
            &["ls-files", "--others", "--exclude-standard", "-z"],
        )?)?);
    }
    let files: Vec<_> = changed
        .iter()
        .filter(|p| !deleted.contains(*p) || root.join(p).exists())
        .map(|p| root.join(p))
        .collect();
    let mut options = crate::scan::options(root.to_string_lossy().into(), &args);
    options.files = files;
    options.explicit_files = true;
    let mut result = sentinel_scanner::run_scan(options);
    result.files.extend(
        deleted
            .into_iter()
            .filter(|p| !root.join(p).exists())
            .map(|p| root.join(p)),
    );
    crate::scan::finish(result, &root, &args)
}
