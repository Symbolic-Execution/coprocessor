/// Test-only sealing helpers: payload sealing, key derivation, and XOR
/// primitives. These remain crate-private; the host never handles plaintext.

pub(crate) struct SealedPayload {
    pub(crate) wrapped_key: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

pub(crate) fn seal_payload(secret: &[u8; 32], aad: &[u8], plaintext: [u8; 32]) -> SealedPayload {
    let keystream = derive_keystream_32(secret, aad);
    SealedPayload {
        wrapped_key: derive_wrapped_key(secret, aad),
        ciphertext: xor32(&plaintext, &keystream).to_vec(),
    }
}

pub(crate) fn unseal_payload(secret: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Option<[u8; 32]> {
    let payload: [u8; 32] = ciphertext.try_into().ok()?;
    let keystream = derive_keystream_32(secret, aad);
    Some(xor32(&payload, &keystream))
}

/// Tiny mixing PRG (FNV-1a + a SplitMix64-style finalizer) keyed by the
/// sealing secret and the AAD bytes. NOT cryptographic. Produces a 32-byte
/// keystream that differs whenever the AAD differs, so each sealed payload is
/// bound to its own AAD.
fn derive_keystream_32(secret: &[u8; 32], aad: &[u8]) -> [u8; 32] {
    let mut state: u64 = 0xcbf29ce4_84222325;
    for &b in secret.iter().chain(aad.iter()) {
        state ^= b as u64;
        state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
    let mut out = [0u8; 32];
    for slot in &mut out {
        state ^= state >> 30;
        state = state.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        state ^= state >> 27;
        state = state.wrapping_mul(0x94D0_49BB_1331_11EB);
        state ^= state >> 31;
        *slot = state as u8;
    }
    out
}

/// Symbolic wrapped-DEK bytes, deterministic per AAD. The Enclave does not
/// use these for unsealing; the keystream is derived directly from the
/// sealing secret and the AAD, but a real MPC-wrapped DEK is non-empty and
/// AAD-bound, and we mirror that here so envelopes look structurally real.
fn derive_wrapped_key(secret: &[u8; 32], aad: &[u8]) -> Vec<u8> {
    let mut state: u64 = 0;
    for &b in secret.iter().chain(aad.iter()) {
        state = state.rotate_left(7) ^ b as u64;
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    let mut out = vec![0u8; 16];
    for chunk in out.chunks_exact_mut(8) {
        state ^= state >> 33;
        state = state.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        chunk.copy_from_slice(&state.to_be_bytes());
    }
    out
}

pub(crate) fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}
