pub trait BoolOptionExt {
    fn b_then<T>(self, t: T) -> Option<T>;

    fn b_then_with<T, F: FnOnce() -> T>(self, f: F) -> Option<T>;
}

impl BoolOptionExt for bool {
    #[inline]
    fn b_then<T>(self, t: T) -> Option<T> {
        if self {
            Some(t)
        } else {
            None
        }
    }
    #[inline]
    fn b_then_with<T, F: FnOnce() -> T>(self, f: F) -> Option<T> {
        if self {
            Some(f())
        } else {
            None
        }
    }
}
