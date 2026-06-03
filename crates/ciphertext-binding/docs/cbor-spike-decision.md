# CBOR Dependency Spike - Decision Record

**Issue:** #84  
**Outcome:** ABANDON - manual CBOR implementation retained

## What was evaluated

`minicbor` 2.2.2 was evaluated as a replacement for the hand-written CBOR
reader/writer in `src/lib.rs` (the `Reader` struct and `write_*` helpers).

## Pass criteria and results

| Criterion | Result |
|-----------|--------|
| (a) Encoder output byte-identical for uint, array, bstr, tstr | **PASS** |
| (b) Non-canonical integer/length rejection on decode (no glue) | **FAIL** |
| (c) Malformed/truncated rejection | PASS |
| (d) AAD-to-envelope binding as domain check | not applicable to codec |
| (e) Errors carry no payload bytes | not applicable (decode rejected at (b)) |
| (f) Net meaningful code deletion | blocked by (b) |

## Why criterion (b) fails

The current implementation rejects non-shortest-form CBOR encodings via the
`min_value` check in `Reader::read_header` (lib.rs). For example:

- `0x18 0x01` (one-byte-extended form of uint 1) is rejected as `NonCanonicalEncoding`
- `0x59 0x00 0x20` (two-byte-extended length for a 32-byte bstr) is rejected
- `0x98 0x04` (one-byte-extended array length for a 4-element array) is rejected

minicbor's decoder accepts all of these without error. From the decoder source:

```rust
pub fn u8(&mut self) -> Result<u8, Error> {
    match self.read()? {
        n @ 0 ..= 0x17 => Ok(n),   // direct form
        0x18           => self.read(),  // accepts 0x18 0x01; no shortest-form check
        0x19           => self.read_array().map(u16::from_be_bytes).and_then(...),
        ...
    }
}
```

This was verified empirically by a spike test that fed non-canonical encodings
to `Decoder::u8()`, `Decoder::bytes()`, and `Decoder::array()`; all returned
`Ok`, confirming that no rejection occurs without a hand-written guard.

## Why this is a blocking gap

Canonical (shortest-form) encoding is a security/protocol invariant for this
codebase: AAD bytes that are not in canonical form are rejected at decode time
to prevent ambiguity attacks (two byte sequences that parse to the same value
but produce different bytes). To maintain this with minicbor, a per-field
shortest-form check would need to be written after each decode call, which
duplicates the existing `read_header` logic field-by-field rather than once
at the header level. That glue volume negates the code-deletion benefit and
re-introduces surface for the same class of bug the current implementation
centralizes.

## Conclusion

The manual `Reader` / `write_*` implementation remains the best choice:

- It centralizes canonical enforcement in one place (`read_header`, 30 lines).
- It produces the exact byte layout the protocol requires.
- It maps directly to the domain error types without a translation layer.
- It carries no transitive dependencies into the crate.

The spike confirmed that minicbor's encoder output is byte-identical (a useful
future data point if the library ever adds a canonical-decode mode), but the
decoder gap is the deciding factor.
