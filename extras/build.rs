use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    if target == "x86_64-linux-android" {
        // Tell cargo to look for shared libraries in the specified directory
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/android/");
    }
}