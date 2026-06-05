/// Domain identifier newtypes and kind discriminants for the Ciphertext
/// Binding AAD and envelope layers.

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DomainId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractAddress(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReaderId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttestationDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AadKind {
    SystemInput,
    SystemHandle,
    Enclave,
    Reader,
}

impl AadKind {
    pub(crate) fn discriminant(self) -> u64 {
        match self {
            AadKind::SystemInput => 1,
            AadKind::SystemHandle => 2,
            AadKind::Enclave => 3,
            AadKind::Reader => 4,
        }
    }

    pub(crate) fn from_discriminant(value: u64) -> Option<Self> {
        Some(match value {
            1 => AadKind::SystemInput,
            2 => AadKind::SystemHandle,
            3 => AadKind::Enclave,
            4 => AadKind::Reader,
            _ => return None,
        })
    }

    pub(crate) fn array_length(self) -> usize {
        match self {
            AadKind::SystemInput | AadKind::SystemHandle => 7,
            AadKind::Enclave | AadKind::Reader => 9,
        }
    }
}

/// Kind discriminant for the three spec-defined ciphertext envelopes that wrap
/// AAD and opaque cryptographic payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeKind {
    System,
    Enclave,
    Reader,
}

impl EnvelopeKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            EnvelopeKind::System => "SystemCiphertextV1",
            EnvelopeKind::Enclave => "EnclaveCiphertextV1",
            EnvelopeKind::Reader => "ReaderCiphertextV1",
        }
    }

    pub(crate) fn aad_matches(self, kind: AadKind) -> bool {
        match self {
            EnvelopeKind::System => {
                matches!(kind, AadKind::SystemInput | AadKind::SystemHandle)
            }
            EnvelopeKind::Enclave => matches!(kind, AadKind::Enclave),
            EnvelopeKind::Reader => matches!(kind, AadKind::Reader),
        }
    }
}
