use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractAddress(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DomainId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleKey {
    pub chain_id: ChainId,
    pub contract_address: ContractAddress,
    pub handle_id: HandleId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleType {
    Suint256,
    Sbool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemCiphertextV1(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationReceipt(pub Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainEventRef {
    pub chain_id: ChainId,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub log_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandleState {
    Ready {
        system_ciphertext: SystemCiphertextV1,
        materialization_receipt: MaterializationReceipt,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleRecord {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub handle_type: HandleType,
    pub state: HandleState,
    pub event_ref: ChainEventRef,
    pub is_canonical: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainEvent {
    ImportedHandle(ImportedHandle),
    PlaintextHandle(PlaintextHandle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedHandle {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub handle_type: HandleType,
    pub system_ciphertext: SystemCiphertextV1,
    pub materialization_receipt: MaterializationReceipt,
    pub event_ref: ChainEventRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPlaintextValue(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextHandle {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub handle_type: HandleType,
    pub public_value: PublicPlaintextValue,
    pub event_ref: ChainEventRef,
}

#[derive(Default)]
pub struct HandleGraphCore {
    records: HashMap<HandleKey, HandleRecord>,
    consumed_events: HashSet<ChainEventRef>,
}

impl HandleGraphCore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_chain_event(&mut self, event: ChainEvent) {
        let event_ref = event.event_ref();
        if !self.consumed_events.insert(event_ref) {
            return;
        }

        match event {
            ChainEvent::ImportedHandle(imported) => {
                self.records.insert(
                    imported.handle_key,
                    HandleRecord {
                        domain_id: imported.domain_id,
                        handle_key: imported.handle_key,
                        handle_type: imported.handle_type,
                        state: HandleState::Ready {
                            system_ciphertext: imported.system_ciphertext,
                            materialization_receipt: imported.materialization_receipt,
                        },
                        event_ref: imported.event_ref,
                        is_canonical: true,
                    },
                );
            }
            ChainEvent::PlaintextHandle(plaintext) => {
                let system_ciphertext = placeholder_plaintext_system_ciphertext(&plaintext);
                let materialization_receipt = placeholder_plaintext_receipt(&plaintext);
                self.records.insert(
                    plaintext.handle_key,
                    HandleRecord {
                        domain_id: plaintext.domain_id,
                        handle_key: plaintext.handle_key,
                        handle_type: plaintext.handle_type,
                        state: HandleState::Ready {
                            system_ciphertext,
                            materialization_receipt,
                        },
                        event_ref: plaintext.event_ref,
                        is_canonical: true,
                    },
                );
            }
        }
    }

    pub fn canonical_handle(&self, handle_key: &HandleKey) -> Option<&HandleRecord> {
        self.records.get(handle_key)
    }
}

impl ChainEvent {
    fn event_ref(&self) -> ChainEventRef {
        match self {
            ChainEvent::ImportedHandle(imported) => imported.event_ref,
            ChainEvent::PlaintextHandle(plaintext) => plaintext.event_ref,
        }
    }
}

fn placeholder_plaintext_system_ciphertext(plaintext: &PlaintextHandle) -> SystemCiphertextV1 {
    let mut bytes = b"plaintext-system-ciphertext-v1-placeholder:".to_vec();
    bytes.extend_from_slice(&plaintext.handle_key.handle_id.0);
    SystemCiphertextV1(bytes)
}

fn placeholder_plaintext_receipt(plaintext: &PlaintextHandle) -> MaterializationReceipt {
    let mut bytes = b"plaintext-materialization-receipt-v1-placeholder:".to_vec();
    bytes.extend_from_slice(&plaintext.handle_key.handle_id.0);
    MaterializationReceipt(bytes)
}
