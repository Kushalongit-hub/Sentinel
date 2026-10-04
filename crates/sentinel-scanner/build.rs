use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let rules_dir = Path::new(&manifest_dir).join("rules");
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("embedded_rules.rs");

    let mut contents = String::from("pub fn embedded_rules() -> Vec<(&'static str, &'static str)> {\n");
    contents.push_str("    vec![\n");

    if rules_dir.exists() {
        collect_yaml(&rules_dir, &mut contents);
    }

    contents.push_str("    ]\n");
    contents.push_str("}\n");
    fs::write(&dest, contents).unwrap();
    println!("cargo:rerun-if-changed=rules");
}

fn collect_yaml(dir: &Path, contents: &mut String) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_yaml(&path, contents);
            } else if let Some(ext) = path.extension() {
                if ext == "yml" || ext == "yaml" {
                    if let Ok(data) = fs::read_to_string(&path) {
                        let rel = path.to_str().unwrap_or("").replace('\\', "/");
                        let escaped = data.replace('\\', "\\\\").replace('"', "\\\"");
                        contents.push_str("        (\"");
                        contents.push_str(&rel);
                        contents.push_str("\", \"");
                        contents.push_str(&escaped);
                        contents.push_str("\"),\n");
                    }
                }
            }
        }
    }
}
