//! Body decoders for the four spec-defined AAD kinds.

use super::aad::{AadDecodeError, EnclaveAadV1, ReaderAadV1, SystemHandleAadV1, SystemInputAadV1};
use super::aad_codec::{read_fixed_bytes, read_text_string, read_uint_field};
use super::cbor::Reader;
use super::identifiers::{
    AadKind, AttestationDigest, ContractAddress, DomainId, HandleId, KeyId, ReaderId, RequestId,
};

pub(crate) fn decode_system_input_body(
    reader: &mut Reader,
    version: u8,
) -> Result<SystemInputAadV1, AadDecodeError> {
    let kind = AadKind::SystemInput;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let contract = ContractAddress(read_fixed_bytes::<20>(reader, kind, "contract")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(SystemInputAadV1 {
        version,
        chain_id,
        domain_id,
        contract,
        type_tag,
        key_id,
    })
}

pub(crate) fn decode_system_handle_body(
    reader: &mut Reader,
    version: u8,
) -> Result<SystemHandleAadV1, AadDecodeError> {
    let kind = AadKind::SystemHandle;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let handle_id = HandleId(read_fixed_bytes(reader, kind, "handle_id")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(SystemHandleAadV1 {
        version,
        chain_id,
        domain_id,
        handle_id,
        type_tag,
        key_id,
    })
}

pub(crate) fn decode_enclave_body(
    reader: &mut Reader,
    version: u8,
) -> Result<EnclaveAadV1, AadDecodeError> {
    let kind = AadKind::Enclave;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let request_id = RequestId(read_fixed_bytes(reader, kind, "request_id")?);
    let handle_id = HandleId(read_fixed_bytes(reader, kind, "handle_id")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let attestation_digest =
        AttestationDigest(read_fixed_bytes(reader, kind, "attestation_digest")?);
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(EnclaveAadV1 {
        version,
        chain_id,
        domain_id,
        request_id,
        handle_id,
        type_tag,
        attestation_digest,
        key_id,
    })
}

pub(crate) fn decode_reader_body(
    reader: &mut Reader,
    version: u8,
) -> Result<ReaderAadV1, AadDecodeError> {
    let kind = AadKind::Reader;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let request_id = RequestId(read_fixed_bytes(reader, kind, "request_id")?);
    let handle_id = HandleId(read_fixed_bytes(reader, kind, "handle_id")?);
    let reader_id = ReaderId(read_fixed_bytes(reader, kind, "reader_id")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(ReaderAadV1 {
        version,
        chain_id,
        domain_id,
        request_id,
        handle_id,
        reader_id,
        type_tag,
        key_id,
    })
}
