use saffron::serialization::from_bytes;

fn main() {
    let bs = vec![5u8];
    let n = from_bytes(&bs);
    println!("Hello, world {}!", n);
}
