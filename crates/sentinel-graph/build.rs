use std::{env, fs, path::Path};
fn main() {
    let root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("audit-skill");
    let mut paths = Vec::new();
    collect(&root, &mut paths);
    paths.sort();
    let mut code = String::from("pub const ASSETS: &[(&str, &str)] = &[\n");
    for path in paths {
        let name = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        code.push_str(&format!(
            "({name:?}, {:?}),\n",
            fs::read_to_string(path).unwrap()
        ));
    }
    code.push_str("];\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("audit_assets.rs"),
        code,
    )
    .unwrap();
    println!("cargo:rerun-if-changed=audit-skill");
}
fn collect(root: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, paths);
        } else {
            paths.push(path);
        }
    }
}
