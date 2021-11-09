use sha3::{Digest, Sha3_256};

fn main() {
    let mut hasher = Sha3_256::new();

    hasher.update(b"abcdefg");

    let result = hasher.finalize();

    println!("{:x?}", result);
}
