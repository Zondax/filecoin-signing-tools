use serde_json::{Result, Value};
use std::fs::File;
use std::io::Read;

pub fn load_test_vectors(path: &str) -> Result<Value> {
    /* Load test vectors */
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let v: Value = serde_json::from_str(&data)?;

    Ok(v)
}
