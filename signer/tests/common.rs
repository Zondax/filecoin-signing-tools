use rustc_serialize::json::Json;
use std::fs::File;
use std::io::Read;

fn load_test_vectors() {
    /* Load test */
    let mut file = File::open("../test_vectors/wallet.json").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let json = Json::from_str(&data).unwrap();
    let private_key = json.find_path(&["private_key"]).unwrap();
}
