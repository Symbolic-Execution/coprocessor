# Do Not Durably Persist Enclave Ciphertexts

The Coprocessor will treat EnclaveCiphertextV1 values as task-scoped inputs to
Enclave Execution, not as durable state. Durable state is limited to Handle
Records, SystemCiphertextV1 for Ready Handles, Materialization Receipts, and
audit/provenance data; this reduces retained sensitive intermediate material
while still preserving enough state for recovery and debugging. The same
retention posture applies to Attestation material: persist attestation digests
or metadata needed for receipts and audit first, not raw Attestation documents
by default. A Derived Handle's Materialization Receipt includes or references
the OperationCode, output Handle Key, ordered input Handle Keys, and Attestation
digest or metadata used for Enclave Execution.
