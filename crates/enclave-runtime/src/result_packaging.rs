/// Local Enclave AAD construction plus input and output envelope packaging.
use coprocessor_ciphertext_binding::{
    EnclaveAadV1, EnclaveCiphertextV1, HandleId as AadHandleId, RequestId, SystemCiphertextV1,
    SystemHandleAadV1,
};
use coprocessor_handle_graph_core::HandleKey;

use crate::ResolutionTask;

use super::local::{LocalEnclaveConfig, AAD_VERSION, ENVELOPE_VERSION};
use super::operation::type_tag_for_handle_type;
use super::sealing::{seal_payload, unseal_payload};

pub(super) fn seal_input(
    config: &LocalEnclaveConfig,
    request_id: RequestId,
    input_handle_key: HandleKey,
    type_tag: &str,
    plaintext: [u8; 32],
) -> EnclaveCiphertextV1 {
    let aad = build_enclave_aad(config, request_id, input_handle_key, type_tag);
    let aad_bytes = aad.encode();
    let sealed = seal_payload(&config.sealing_secret, &aad_bytes, plaintext);
    EnclaveCiphertextV1 {
        version: ENVELOPE_VERSION,
        aad: aad_bytes,
        wrapped_key: sealed.wrapped_key,
        ciphertext: sealed.ciphertext,
    }
}

pub(super) fn unseal_output(
    config: &LocalEnclaveConfig,
    ciphertext: &SystemCiphertextV1,
    expected_type_tag: &str,
) -> Option<[u8; 32]> {
    let aad = SystemHandleAadV1::decode(&ciphertext.aad).ok()?;
    if aad.version != AAD_VERSION
        || aad.chain_id != config.chain_id
        || aad.domain_id != config.domain_id
        || aad.type_tag != expected_type_tag
        || aad.key_id != config.system_key_id
    {
        return None;
    }
    unseal_payload(
        &config.sealing_secret,
        &ciphertext.aad,
        &ciphertext.ciphertext,
    )
}

pub(super) fn seal_output(
    config: &LocalEnclaveConfig,
    task: &ResolutionTask,
    plaintext: [u8; 32],
) -> SystemCiphertextV1 {
    let type_tag = type_tag_for_handle_type(task.output_handle_type);
    let aad = SystemHandleAadV1 {
        version: AAD_VERSION,
        chain_id: config.chain_id,
        domain_id: config.domain_id,
        handle_id: AadHandleId(task.output_handle_key.handle_id.0),
        type_tag: type_tag.to_string(),
        key_id: config.system_key_id,
    };
    let aad_bytes = aad.encode();
    let sealed = seal_payload(&config.sealing_secret, &aad_bytes, plaintext);
    SystemCiphertextV1 {
        version: ENVELOPE_VERSION,
        aad: aad_bytes,
        wrapped_key: sealed.wrapped_key,
        ciphertext: sealed.ciphertext,
    }
}

fn build_enclave_aad(
    config: &LocalEnclaveConfig,
    request_id: RequestId,
    input_handle_key: HandleKey,
    type_tag: &str,
) -> EnclaveAadV1 {
    EnclaveAadV1 {
        version: AAD_VERSION,
        chain_id: config.chain_id,
        domain_id: config.domain_id,
        request_id,
        handle_id: AadHandleId(input_handle_key.handle_id.0),
        type_tag: type_tag.to_string(),
        attestation_digest: config.attestation_digest,
        key_id: config.enclave_key_id,
    }
}
