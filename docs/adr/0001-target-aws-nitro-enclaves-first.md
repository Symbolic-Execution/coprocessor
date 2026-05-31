# Target AWS Nitro Enclaves First

The first production Coprocessor will target AWS Nitro Enclaves for private
execution. The domain language remains runtime-neutral: `Enclave` means the
private computation side of the Coprocessor, while Nitro-specific attestation,
packaging, deployment, and local development concerns belong in implementation
adapters.
