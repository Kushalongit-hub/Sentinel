//! Bounded, argument-safe Git selection shared by CLI and security services.
use crate::{ScannerError, SubprocessRunner};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Repository-relative changed and deleted paths, including untracked working-tree files.
#[derive(Debug, Clone)]
pub struct Changes {
    pub root: PathBuf,
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
    pub base_commit: Option<String>,
}
/// Execute a Git read operation without shell interpolation and with bounded output.
pub fn read(root: &Path, args: &[&str], max_bytes: usize) -> crate::Result<String> {
    let mut command = Command::new("git");
    command
        .args(["--no-pager", "-c", "core.fsmonitor=false"])
        .arg("-C")
        .arg(root);
    if args.first() == Some(&"diff") {
        command
            .args(["diff", "--no-ext-diff", "--no-textconv"])
            .args(&args[1..]);
    } else {
        command.args(args);
    }
    let result = SubprocessRunner::run_command(&mut command, Duration::from_secs(15), max_bytes)?;
    if let Some(error) = result.execution_error {
        return Err(ScannerError::Parse(format!("Git failed: {error}")));
    }
    Ok(result.stdout)
}
/// Resolve a user-supplied ref to an immutable commit before passing it to other commands.
pub fn commit(root: &Path, reference: &str) -> crate::Result<String> {
    let revision = format!("{reference}^{{commit}}");
    let value = read(
        root,
        &["rev-parse", "--verify", "--end-of-options", &revision],
        4096,
    )?;
    let value = value.trim();
    if ![40, 64].contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ScannerError::Parse("Git did not resolve a commit".into()));
    }
    Ok(value.into())
}
/// Select staged, unstaged, and optionally untracked files, or compare against a base ref.
pub fn changes(
    root: &Path,
    base: Option<&str>,
    staged: bool,
    unstaged: bool,
    tracked_only: bool,
) -> crate::Result<Changes> {
    let repo = PathBuf::from(
        read(root, &["rev-parse", "--show-toplevel"], 32768)?.trim_end_matches(['\r', '\n']),
    )
    .canonicalize()
    .map_err(|e| ScannerError::Parse(e.to_string()))?;
    let base_commit = base.map(|r| commit(&repo, r)).transpose()?;
    let mut selected = BTreeSet::new();
    if let Some(base) = &base_commit {
        selected.extend(
            read(
                &repo,
                &["diff", "--name-only", "-z", base, "--"],
                4 * 1024 * 1024,
            )?
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        );
    } else {
        if !unstaged {
            selected.extend(
                read(
                    &repo,
                    &["diff", "--cached", "--name-only", "-z", "--"],
                    4 * 1024 * 1024,
                )?
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            );
        }
        if !staged {
            selected.extend(
                read(&repo, &["diff", "--name-only", "-z", "--"], 4 * 1024 * 1024)?
                    .split('\0')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    if !tracked_only && !staged && !unstaged {
        selected.extend(
            read(
                &repo,
                &["ls-files", "--others", "--exclude-standard", "-z"],
                4 * 1024 * 1024,
            )?
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        );
    }
    let mut changed = vec![];
    let mut deleted = vec![];
    for path in selected {
        if sentinel_ast::should_skip(Path::new(&path)) {
            continue;
        }
        if repo.join(&path).exists() {
            changed.push(path);
        } else {
            deleted.push(path);
        }
    }
    Ok(Changes {
        root: repo,
        changed,
        deleted,
        base_commit,
    })
}
/// Read a bounded UTF-8 blob from a validated commit; never check it out or execute it.
pub fn source_at(root: &Path, commit: &str, path: &str) -> crate::Result<String> {
    if ![40, 64].contains(&commit.len()) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ScannerError::Parse(
            "expected an immutable Git commit".into(),
        ));
    }
    let object = format!("{commit}:{path}");
    read(root, &["show", &object], 1024 * 1024)
}
