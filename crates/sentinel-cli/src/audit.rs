use crate::ScanArgs;
use anyhow::Result;
pub fn audit(path: String) -> Result<i32> {
    audit_with_options(path, ScanArgs::default())
}
pub fn audit_with_options(path: String, args: ScanArgs) -> Result<i32> {
    let target = std::path::Path::new(&path).canonicalize()?;
    let result =
        sentinel_scanner::run_scan(crate::scan::options(target.to_string_lossy().into(), &args));
    crate::scan::finish(result, &target, &args)
}
