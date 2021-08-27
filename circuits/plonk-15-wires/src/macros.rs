/// checks if two expressions are equal, if not return false
macro_rules! ensure_eq {
    ($a:expr, $b:expr) => {
        if $a != $b {
            return false;
        }
    };
}
