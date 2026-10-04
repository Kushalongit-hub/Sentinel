use anyhow::Result;

pub fn rules() -> Result<i32> {
    let db = match sentinel_db::SentinelDb::new(".sentinel.db") {
        Ok(db) => db,
        Err(_) => {
            println!("No local database found. Run `sentinel audit` first.");
            return Ok(0);
        }
    };

    match db.list_rules() {
        Ok(rules) => {
            if rules.is_empty() {
                println!("No rules found.");
            } else {
                for (id, name) in rules {
                    println!("{} - {}", id, name);
                }
            }
        }
        Err(_) => {
            println!("Error retrieving rules.");
        }
    }

    Ok(0)
}
