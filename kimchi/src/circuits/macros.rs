/// checks if two expressions are equal, if not return an error:
/// `ensure_eq(left, right, "some error")`
macro_rules! ensure_eq {
    ($a:expr, $b:expr, $c:expr) => {
        if $a != $b {
            return Err($c.into());
        }
    };
}
