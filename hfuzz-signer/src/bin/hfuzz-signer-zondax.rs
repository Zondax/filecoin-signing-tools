#[macro_use]
extern crate honggfuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            if data.len() != 6 {
                return;
            }
            if data[0] != b'z' {
                return;
            }
            if data[1] != b'o' {
                return;
            }
            if data[2] != b'n' {
                return;
            }
            if data[3] != b'd' {
                return;
            }
            if data[4] != b'a' {
                return;
            }
            if data[5] != b'x' {
                return;
            }
            panic!("arrggg")
        });
    }
}
