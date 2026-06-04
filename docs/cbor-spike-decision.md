# CBOR Dependency Spike - Decision Record

**Issue:** #84
**Outcome:** ABANDON - manual CBOR implementation retained

## What Was Evaluated

`minicbor` 2.2.2 was evaluated as a replacement for the hand-written CBOR
reader/writer in `crates/ciphertext-binding/src/lib.rs` (the `Reader` struct
and `write_*` helpers).

## Pass Criteria And Results

The spike used five pass criteria, plus one code-deletion viability check:

| Criterion | Result |
|-----------|--------|
| (a) Encoder output byte-identical for uint, array, bstr, tstr | **PASS** |
| (b) Non-canonical integer/length rejection on decode without glue | **FAIL** |
| (c) Malformed/truncated rejection | **PASS** |
| (d) AAD-to-envelope binding remains a domain check | Not applicable to codec |
| (e) Errors carry no payload bytes | Not applicable after (b) failure |
| Code-deletion viability | Blocked by (b) |

## Why Criterion (b) Fails

The current implementation rejects non-shortest-form CBOR encodings via the
`min_value` check in `Reader::read_header`. For example:

- `0x18 0x01` (one-byte-extended form of uint 1) is rejected as `NonCanonicalEncoding`
- `0x59 0x00 0x20` (two-byte-extended length for a 32-byte bstr) is rejected
- `0x98 0x04` (one-byte-extended array length for a 4-element array) is rejected

`minicbor`'s decoder accepts all of these without error. From the 2.2.2 decoder
source:

```rust
pub fn u8(&mut self) -> Result<u8, Error> {
    match self.read()? {
        n @ 0 ..= 0x17 => Ok(n),
        0x18           => self.read(),
        0x19           => self.read_array().map(u16::from_be_bytes).and_then(...),
        ...
    }
}
```

The same pattern applies to decoded integer and length headers: the decoder
reads the encoded argument form and returns the semantic value without checking
that the shortest available CBOR form was used.

This was verified empirically by a throwaway spike test that fed non-canonical
encodings to `Decoder::u8()`, `Decoder::bytes()`, and `Decoder::array()`. All
three returned `Ok`, confirming that no rejection occurs without a hand-written
guard.

## Why This Is Blocking

Canonical shortest-form encoding is a security and protocol invariant for this
codebase. AAD bytes that are not in canonical form are rejected at decode time
to prevent ambiguity attacks where two byte sequences parse to the same value
but bind different bytes.

To maintain this with `minicbor`, the crate would need per-field shortest-form
guards after decode calls. That would duplicate the existing `read_header`
logic field by field rather than enforcing it once at the header level. The
required glue negates the code-deletion rationale and reintroduces surface for
the same class of bug the current implementation centralizes.

## Committed Artifacts

- `docs/cbor-spike-decision.md`: this decision record.
- `crates/ciphertext-binding/src/lib.rs`: module documentation pointing to this
  decision record and explaining why the manual codec remains intentional.

No dependency was added to `crates/ciphertext-binding/Cargo.toml`, and no AAD or
envelope encoded bytes were changed.

## Conclusion

The manual `Reader` / `write_*` implementation remains the best choice:

- It centralizes canonical enforcement in one place (`read_header`).
- It produces the exact byte layout the protocol requires.
- It maps directly to the domain error types without a translation layer.
- It carries no transitive dependencies into the crate.

The spike confirmed that `minicbor`'s encoder output is byte-identical, which
may be useful if the library later adds a canonical-decode mode. The decoder
gap is the deciding factor for this issue.
