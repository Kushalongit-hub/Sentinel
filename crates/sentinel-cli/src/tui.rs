use anyhow::Result;
use std::io::{self, Write};

pub fn run() -> Result<()> {
    loop {
        print_menu();
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        match input {
            "1" => prompt_audit()?,
            "2" => prompt_diff()?,
            "3" => prompt_explain()?,
            "4" => prompt_rules()?,
            "5" => {
                println!("Exiting.");
                break;
            }
            _ => println!("Invalid option. Choose 1-5."),
        }

        println!();
    }

    Ok(())
}

fn print_menu() {
    println!("Sentinel TUI");
    println!("1. Audit <path>");
    println!("2. Diff");
    println!("3. Explain <finding_id>");
    println!("4. Rules");
    println!("5. Exit");
}

fn prompt_audit() -> Result<()> {
    print!("Path to audit: ");
    io::stdout().flush()?;
    let mut path = String::new();
    io::stdin().read_line(&mut path)?;
    let path = path.trim();

    if path.is_empty() {
        println!("No path provided.");
        return Ok(());
    }

    crate::audit::audit(path.to_string())
}

fn prompt_diff() -> Result<()> {
    crate::diff::diff()
}

fn prompt_explain() -> Result<()> {
    print!("Finding ID: ");
    io::stdout().flush()?;
    let mut id = String::new();
    io::stdin().read_line(&mut id)?;
    let id = id.trim();

    if id.is_empty() {
        println!("No finding ID provided.");
        return Ok(());
    }

    crate::explain::explain(id.to_string())
}

fn prompt_rules() -> Result<()> {
    crate::rules::rules()
}
