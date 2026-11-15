#[path = "../journal.rs"]
#[allow(dead_code)]
mod journal;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args_os()
        .nth(2)
        .ok_or("usage: journal JOURNAL_FILE BASE_FILE")?;
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: journal JOURNAL_FILE")?;
    let mut reader =
        journal::JournalReader::open(std::path::Path::new(&path), std::path::Path::new(&base))?;
    let (mut records, mut publications) = (0, 0);
    while let Some(event) = reader.next()? {
        match event {
            journal::Event::Object { .. } => records += 1,
            journal::Event::Publication { .. } => publications += 1,
        }
    }
    let retained =
        journal::retained_records(std::path::Path::new(&path), std::path::Path::new(&base))?;
    println!(
        "{}",
        serde_json::json!({"records":records,"publications":publications,"latest_generation":retained.generation,"retained_records":retained.selected.iter().filter(|live| **live).count(),"retained_payload_bytes":retained.retained_payload_bytes,"total_payload_bytes":retained.total_payload_bytes})
    );
    Ok(())
}
