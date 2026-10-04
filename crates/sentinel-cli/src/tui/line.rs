use anyhow::Result;
use std::io::{self, Write};

pub fn run() -> Result<i32> {
    loop {
        print_menu();
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            println!();
            break;
        }
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input {
            "1" => {
                if let Err(e) = prompt_audit() {
                    eprintln!("[error] {}", e);
                }
            }
            "2" => {
                if let Err(e) = prompt_diff() {
                    eprintln!("[error] {}", e);
                }
            }
            "3" => {
                if let Err(e) = prompt_explain() {
                    eprintln!("[error] {}", e);
                }
            }
            "4" => {
                if let Err(e) = prompt_rules() {
                    eprintln!("[error] {}", e);
                }
            }
            "5" => {
                println!("Exiting.");
                break;
            }
            _ => println!("Invalid option. Choose 1-5."),
        }

        println!();
    }

    Ok(0)
}

fn print_menu() {
    println!("Sentinel TUI");
    println!("1. Audit <path>");
    println!("2. Diff");
    println!("3. Explain <finding_id>");
    println!("4. Rules");
    println!("5. Exit");
}

fn prompt_audit() -> Result<i32> {
    print!("Path to audit: ");
    io::stdout().flush()?;
    let mut path = String::new();
    io::stdin().read_line(&mut path)?;
    let path = path.trim();

    if path.is_empty() {
        println!("No path provided.");
        return Ok(0);
    }

    crate::audit::audit(path.to_string())
}

fn prompt_diff() -> Result<i32> {
    crate::diff::diff()
}

fn prompt_explain() -> Result<i32> {
    print!("Finding ID: ");
    io::stdout().flush()?;
    let mut id = String::new();
    io::stdin().read_line(&mut id)?;
    let id = id.trim();

    if id.is_empty() {
        println!("No finding ID provided.");
        return Ok(0);
    }

    crate::explain::explain(id.to_string())
}

fn prompt_rules() -> Result<i32> {
    crate::rules::rules()
}
