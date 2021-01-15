fn main() {
    use wasm_bindgen_test::*;
    
    #[wasm_bindgen_test]
    fn pass2() {
        assert_eq!(1, 1);
    }
    
    #[wasm_bindgen_test]
    fn fail2() {
        assert_eq!(2, 2);
    }
    }
    