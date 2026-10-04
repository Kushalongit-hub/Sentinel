use crate::ScanArgs;
use anyhow::Result;
pub fn diff() -> Result<i32> {
    diff_with_options(ScanArgs::default(), false, false, false)
}
pub fn diff_with_options(
    args: ScanArgs,
    staged: bool,
    unstaged: bool,
    tracked_only: bool,
) -> Result<i32> {
    let changes = sentinel_scanner::git::changes(
        std::path::Path::new("."),
        None,
        staged,
        unstaged,
        tracked_only,
    )?;
    let root = changes.root;
    let mut options = crate::scan::options(root.to_string_lossy().into(), &args);
    options.files = changes.changed.into_iter().map(|p| root.join(p)).collect();
    options.explicit_files = true;
    let mut result = sentinel_scanner::run_scan(options);
    result
        .files
        .extend(changes.deleted.into_iter().map(|p| root.join(p)));
    crate::scan::finish(result, &root, &args)
}
