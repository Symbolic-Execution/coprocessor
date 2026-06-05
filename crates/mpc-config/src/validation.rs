/// Hex/public-key validation helpers.

pub(super) fn to_fixed<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}
