//! Utilities module

// Functionalities for types that operate on blocks
pub mod block;

macro_rules! majority {
    ($a:expr, $b:expr, $c:expr) => {
        ($a & $b) ^ ($a & $c) ^ ($b & $c)
    };
}
pub(crate) use majority;

macro_rules! choice {
    ($a:expr, $b:expr, $c:expr) => {
        ($a & $b) ^ (!$a & $c)
    };
}
pub(crate) use choice;
