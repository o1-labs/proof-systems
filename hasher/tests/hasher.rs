mod test_vector;
use test_vector::*;

//
// Tests
//

#[test]
fn hasher_test_vectors_legacy() {
    let mut hasher = mina_hasher::create_legacy::<TestVector>(());
    test_vectors("legacy.json", &mut hasher);
}

#[test]
fn hasher_test_vectors_kimchi() {
    let mut hasher = mina_hasher::create_kimchi::<TestVector>(());
    test_vectors("kimchi.json", &mut hasher);
}
