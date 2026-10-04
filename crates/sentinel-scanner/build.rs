use std::{env, fs, path::Path};
fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").unwrap();
    let rules = Path::new(&root).join("rules");
    let mut paths = vec![];
    collect(&rules, &mut paths);
    paths.sort();
    assert!(!paths.is_empty(), "bundled rule directory is empty");
    let mut code =
        String::from("pub fn embedded_rules() -> Vec<(&'static str, &'static str)> { vec![\n");
    for path in paths {
        let data = fs::read_to_string(&path).expect("cannot read bundled rule");
        let name = path
            .strip_prefix(&rules)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        code.push_str(&format!("({name:?}, {data:?}),\n"));
    }
    code.push_str("] }");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("embedded_rules.rs"),
        code,
    )
    .unwrap();
    println!("cargo:rerun-if-changed=rules");
}
fn collect(dir: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("cannot read bundled rule directory") {
        let path = entry.expect("cannot read rule entry").path();
        if path.is_dir() {
            collect(&path, paths);
        } else if path
            .extension()
            .map(|e| e == "yml" || e == "yaml")
            .unwrap_or(false)
        {
            paths.push(path);
        }
    }
}
