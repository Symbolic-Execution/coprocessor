# Coprocessor

The coprocessor context describes the off-chain private execution system for
Symbolic Execution. Its language centers on handles, symbolic work, and the
division between orchestration and private computation.

## Language

**Coprocessor**:
The off-chain private execution system that resolves symbolic work produced by
`symVM`. A coprocessor includes both the Coprocessor Host and the Enclave.
_Avoid_: Host, worker, executor

**Coprocessor Host**:
The non-private orchestration side of the Coprocessor. It observes chain events,
tracks handle state, schedules resolution, calls MPC, and exposes handle state
to the Coordinator.
_Avoid_: Coprocessor, service, backend

**Enclave**:
The private computation side of the Coprocessor. It is the only part of the
Coprocessor that may decrypt enclave-targeted ciphertexts or evaluate private
values.
_Avoid_: Coprocessor, worker, execution engine

**sym-client**:
The user-facing SDK that encrypts private inputs, manages reader keys, requests
Disclosure, and decrypts ReaderCiphertextV1 locally.
_Avoid_: Client, frontend, wallet

**symVM**:
The on-chain handle registry and canonical event surface for Symbolic
Operations.
_Avoid_: Contract, VM, chain

**Coordinator**:
The public control plane for authorization, async request tracking, Disclosure,
and routing between sym-client, the Coprocessor, and MPC.
_Avoid_: Coprocessor, API server, gateway

**MPC**:
The threshold key custody and ciphertext transformation system. MPC returns
ciphertexts, not plaintext or unilateral decryption material.
_Avoid_: Key server, decryptor, crypto service

**Handle**:
An opaque on-chain reference to a private or symbolic value in a `symVM` domain.
A Handle is not a ciphertext, not plaintext, and not permission to disclose the
underlying value.
_Avoid_: Ciphertext, value, secret

**Private Value**:
The plaintext value referenced by a Handle. A Private Value may be evaluated
inside the Enclave during Resolution or decrypted by an authorized Reader after
Disclosure, but it must not be visible to the Coprocessor Host.
_Avoid_: Handle, ciphertext, payload

**Private Input**:
A user-provided Private Value encrypted by sym-client as SystemCiphertextV1
before import into `symVM`.
_Avoid_: Imported Handle, ciphertext, user value

**Public Plaintext Value**:
A public value emitted by `HandleFromPlaintextV1` and later packaged as
SystemCiphertextV1 so it can participate in Symbolic Operations.
_Avoid_: Constant, private value, raw value

**HandleId**:
The deterministic identifier assigned by `symVM` to a Handle. It identifies the
Handle but does not itself carry the private value.
_Avoid_: Handle, ciphertext id, value id

**Handle Key**:
The tuple `(ChainId, Contract Address, HandleId)` used by the Coprocessor to
identify a Handle Record for resolution and API reads.
_Avoid_: HandleId, primary key, cache key

**ChainId**:
The identifier of the Ethereum chain where a Handle, Chain Event, or Ciphertext
Binding is valid.
_Avoid_: Chain, network, chain view

**RequestId**:
The identifier of a particular request flow, such as a Handle Resolution Request
or To-Enclave Transformation. A RequestId does not identify a Handle.
_Avoid_: HandleId, job id, correlation id

**Contract Address**:
The Ethereum address recorded by `symVM` for the contract that created or
expressed a Handle. It is part of the Handle Key.
_Avoid_: Contract, creating contract, owner

**HandleType**:
The type of value referenced by a Handle. The initial HandleTypes are
`suint256` and `sbool`.
_Avoid_: Solidity type, ciphertext type

**Handle Graph**:
The Coprocessor's dependency model for symbolic work. Its nodes are Handles,
and its edges are ordered operation inputs reconstructed from `symVM` logs.
_Avoid_: Symbolic graph, dependency graph, expression tree

**Handle Lineage**:
The ancestry of a Handle through Source Handles and Derived Handles in the
Handle Graph. Handle Lineage determines dependency readiness and how Orphan
Discard cascades.
_Avoid_: Lineage, ancestry, provenance

**Lineage Violation**:
A canonical Chain Event that contradicts Handle lineage rules, such as creating
the same Handle Key more than once or referencing an input Handle that was not
previously observed in the same DomainId. Lineage Violations lead to Failed for
the affected canonical Handle, not Orphan Discard.
_Avoid_: Orphan, reorg, duplicate event

**Handle State**:
The resolution state of a Handle as known by the Coprocessor. Its variants are
`Pending`, `Ready`, and `Failed`; state-specific values belong to the variant
that makes them valid.
_Avoid_: Handle record, handle metadata, handle type

**Pending**:
A Handle State for a Canonical Handle Record whose Resolution is not complete.
Pending includes waiting for input Handles, active Resolution, and transient
backend unavailability while retries remain.
_Avoid_: Queued, running, unresolved

Pending only applies to known Canonical Handle Records. Unknown Handle Keys are
not Pending.

**Ready**:
A Handle State for a Canonical Handle Record whose value is materialized as
SystemCiphertextV1 and bound with a Materialization Receipt.
_Avoid_: Complete, resolved, materialized

**Materialization**:
The act of binding SystemCiphertextV1 and a Materialization Receipt to a Handle,
making its Handle State Ready.
_Avoid_: Resolution, execution, disclosure

**Symbolic Operation**:
An operation expressed by a contract over Handles, with resolution deferred to
the Coprocessor.
_Avoid_: Computation, transaction, function call

**OperationCode**:
The spec-defined discriminant that identifies which Symbolic Operation a
Derived Handle represents.
_Avoid_: OperationType, opcode, method

**Operation Violation**:
A canonical Symbolic Operation whose OperationCode, arity, input HandleTypes, or
output HandleType violates the operation rules. Operation Violations lead to
Failed for the affected Derived Handle.
_Avoid_: Lineage Violation, execution failure, invalid event

**Select**:
The private conditional-choice Symbolic Operation. Its ordered inputs are
predicate, when true, and when false; the selected branch is not revealed to the
contract at expression time.
_Avoid_: If, branch, ternary

**Handle Resolution Request**:
The Coordinator's internal request asking the Coprocessor to return or begin
Resolution for a Handle. It is not a user Disclosure Request.
_Avoid_: Disclosure request, read request, job request

A Handle Resolution Request does not create Handle Records. Chain Event
Ingestion is the only source of Handle Records.

**Internal Coordinator API**:
The Coprocessor's backend API surface used by the Coordinator to request
Resolution and fetch Canonical Handle Records.
_Avoid_: Public API, client API, disclosure API

**To-Enclave Transformation**:
The MPC operation that validates bindings and transforms SystemCiphertextV1
into EnclaveCiphertextV1 for an attested Enclave key. It includes
re-encryption but is not merely re-encryption.
_Avoid_: Decryption, unwrap, key release

**To-Reader Transformation**:
The MPC operation that transforms SystemCiphertextV1 into ReaderCiphertextV1
for a registered reader. The Coordinator uses To-Reader Transformation; the
Coprocessor does not.
_Avoid_: Disclosure, decryption, coprocessor output

**Attestation**:
Evidence that binds an Enclave public key to an approved Enclave measurement.
MPC checks Attestation before To-Enclave Transformation.
_Avoid_: Proof, certificate, token

**Enclave Measurement**:
The measurement value used to identify an approved Enclave. MPC authorizes
To-Enclave Transformation only when Attestation binds the Enclave key to an
approved Enclave Measurement.
_Avoid_: Version, hash, runtime id

**Ciphertext Binding**:
The authenticated context carried in ciphertext AAD that ties encrypted payloads
to chain, domain, handle, type, key, request, reader, or attestation facts
depending on the ciphertext envelope.
_Avoid_: Metadata, annotation, tag

**DomainId**:
The identifier of the `symVM` domain in which Handles, Chain Events, and
Ciphertext Bindings are valid.
_Avoid_: Domain, EIP-712 domain, network id

**Failed**:
A terminal Handle State for a Canonical Handle Record whose Resolution cannot
complete because validation, MPC transformation, Enclave Execution, or result
packaging failed. Failed carries a reason or category, but does not include
Orphan Discard.
_Avoid_: Orphaned, tombstoned, unknown

Initial Failed categories are `LineageViolation`, `OperationViolation`,
`MpcTransformationFailure`, `EnclaveExecutionFailure`, and
`MaterializationFailure`.

**Materialization Receipt**:
Evidence recorded by the Coprocessor for why a Handle is Ready. Imported,
Plaintext, and Derived Handles may have different receipt sources, but Ready
always includes SystemCiphertextV1 and a Materialization Receipt.
_Avoid_: Proof, attestation, log

For Derived Handles, the Materialization Receipt includes or references the
OperationCode, output Handle Key, ordered input Handle Keys, and Attestation
digest or metadata used for Enclave Execution.

**Handle Record**:
The Coprocessor's durable record for a known Handle. It includes Handle
identity, HandleType, lineage, source event metadata, and Handle State.
_Avoid_: Handle State, handle entry, stored handle

**Source Handle**:
A Handle that becomes ready during chain event ingestion rather than by
resolving an operation. Imported Handles and Plaintext Handles are Source
Handles.
_Avoid_: Input handle, root handle

**Imported Handle**:
A Source Handle created from a Private Input. It is seeded by the
SystemCiphertextV1 carried in `HandleImportedV1`.
_Avoid_: Input Handle, encrypted handle, client handle

**Plaintext Handle**:
A Source Handle created from a Public Plaintext Value. The source value was
public on-chain; the term does not mean the Handle stores plaintext.
_Avoid_: Public handle, constant handle, raw handle

**Derived Handle**:
A Handle created by a symbolic operation. A Derived Handle becomes ready only
after its input Handles are ready and its operation is resolved.
_Avoid_: Output handle, computed handle, result handle

**Resolution**:
The Coprocessor process that turns a Pending Derived Handle into either Ready
or Failed. Resolution includes obtaining ready inputs, transforming ciphertexts
to the Enclave, enclave execution, and binding the encrypted result or failure.
_Avoid_: Execution, computation, fulfillment

**Enclave Execution**:
The private operation-evaluation step inside the Enclave during Resolution. It
is only one part of Resolution.
_Avoid_: Resolution, computation, processing

**Resolution Task**:
The host-scheduled unit of work for resolving one Derived Handle. It carries
the output Handle identity, operation, output type, ordered input Handles, and
ready input ciphertexts.
_Avoid_: Execution task, job, work item

**Resolution Readiness**:
The condition that a Derived Handle's ordered input Handles are all Ready and
canonical, so the Coprocessor Host may create a Resolution Task.
_Avoid_: Schedulable, executable, unblocked

**Resolution Scheduler**:
The Coprocessor Host role that observes Resolution Readiness, deduplicates
repeated work for the same Handle, creates Resolution Tasks, and records the
resulting Handle State.
_Avoid_: Scheduler, worker, job runner

**SystemCiphertextV1**:
The system-held encrypted value used as durable private state for a Handle.
Ready Handles expose their value to backend services as SystemCiphertextV1, not
as plaintext.
_Avoid_: Handle, plaintext, encrypted handle

**EnclaveCiphertextV1**:
A ciphertext transformed for an attested Enclave key during Resolution. The
Coprocessor Host receives it from MPC and passes it to the Enclave.
_Avoid_: SystemCiphertextV1, plaintext, enclave input

**ReaderCiphertextV1**:
A ciphertext transformed for an authorized reader. It is part of the
Coordinator and MPC disclosure flow, not a Coprocessor output.
_Avoid_: SystemCiphertextV1, disclosure result, plaintext

**Reader**:
An authorized holder of a registered reader key that can decrypt
ReaderCiphertextV1. Reader authorization and registration are Coordinator
responsibilities, not Coprocessor responsibilities.
_Avoid_: User, controller, recipient

**Disclosure**:
The Coordinator-led process that turns a Ready Handle's SystemCiphertextV1 into
ReaderCiphertextV1 for an authorized Reader. Disclosure is not Resolution and
does not happen inside the Coprocessor.
_Avoid_: Resolution, read, reveal

**symVM Event Surface**:
The canonical on-chain log surface consumed by the Coprocessor to reconstruct
Handle lineage and dependencies.
_Avoid_: Contract events, log stream, calldata

**Chain Event**:
A single consumed event from the symVM Event Surface, interpreted together with
its chain metadata. Chain Event is the normalized domain input after raw chain
logs are decoded.
_Avoid_: Log, transaction, calldata

**ChainEventRef**:
The provenance reference for a consumed Chain Event in a particular chain view.
It links a Handle Record back to the canonical on-chain event that created it.
_Avoid_: Event metadata, log id, receipt id

**Chain View**:
The confirmation view from which the Coprocessor consumes the symVM Event
Surface. The default Chain View is `safe`; a deployment may choose a stricter
view such as `finalized`.
_Avoid_: Network, block source, confirmation mode

**Chain Event Ingestion**:
The Coprocessor Host process that consumes the symVM Event Surface from the
chosen Chain View, validates lineage, handles canonicality changes, and updates
Handle Records.
_Avoid_: Event listener, log sync, indexer

The Coprocessor reads chain metadata and the symVM Event Surface, not arbitrary
application contract state or calldata.

**Orphan Discard**:
The Coprocessor action of removing orphan-derived Handle Records from normal
resolution and API reads. Orphan Discard tombstones affected records for
auditability rather than treating them as Failed handles, and cascades through
Derived Handles that depend on orphaned lineage.
_Avoid_: Failure, rollback, deletion

**Canonical Handle Record**:
A Handle Record whose ChainEventRef still belongs to the chosen Chain View.
Only Canonical Handle Records participate in normal resolution and API reads.
_Avoid_: Active handle, valid handle, live row

## Example Dialogue

Developer: "Does the Coprocessor decrypt the value?"

Domain expert: "The Enclave decrypts enclave-targeted ciphertexts. The
Coprocessor Host only schedules that work and records the encrypted result."

Developer: "Which system authorizes a user's Disclosure request?"

Domain expert: "The Coordinator. The Coprocessor resolves Handles and returns
SystemCiphertextV1 for Ready Handles."

Developer: "Can I pass a Handle to another contract?"

Domain expert: "Yes, but possessing a Handle is not disclosure permission. It
is only an opaque reference whose operation use and disclosure are authorized
separately."

Developer: "Can the Coprocessor Host log the value for debugging?"

Domain expert: "No. A Private Value must not be visible to the Coprocessor
Host."

Developer: "Does the Coprocessor receive Private Inputs?"

Domain expert: "It receives SystemCiphertextV1 for Imported Handles, not the
Private Input plaintext."

Developer: "Is every value from `fromPlaintext` a constant?"

Domain expert: "No. Use Public Plaintext Value. It is public plaintext, but not
necessarily a semantic constant."

Developer: "Is HandleId enough to identify a record?"

Domain expert: "No. The Coprocessor uses a Handle Key: ChainId, Contract
Address, and HandleId."

Developer: "Can I use RequestId as the handle lookup key?"

Domain expert: "No. RequestId identifies a request flow. Handle Key identifies
the Handle Record."

Developer: "Can I evaluate the Handle Graph without preserving input order?"

Domain expert: "No. Operation inputs are ordered. For `Select`, the inputs are
predicate, when true, then when false."

Developer: "Why did this Derived Handle get tombstoned if its own event is
canonical?"

Domain expert: "Its Handle Lineage depends on a tombstoned Handle Record, so
Orphan Discard cascades to it."

Developer: "What if two canonical events create the same Handle Key?"

Domain expert: "That is a Lineage Violation. Preserve the first canonical
record and fail the later affected Handle."

Developer: "Should an operation wait for an input Handle that appears in a
future log?"

Domain expert: "No. Operation inputs must already be known in canonical log
order. A missing input is a Lineage Violation."

Developer: "Is the HandleType inside Handle State?"

Domain expert: "No. HandleType is metadata about the Handle. Handle State only
describes whether resolution is pending, ready, or failed, with payloads that
belong to those states."

Developer: "Can a Ready Handle lack a receipt?"

Domain expert: "No. Ready means the Handle has SystemCiphertextV1 and a
Materialization Receipt, even when the receipt came from ingestion or plaintext
materialization instead of enclave execution."

Developer: "Should the Internal Coordinator API return receipts for Source
Handles?"

Domain expert: "Yes. Whenever it returns a Ready Handle, it returns
SystemCiphertextV1 and the Materialization Receipt."

Developer: "If a canonical operation has invalid arity, is the handle orphaned?"

Domain expert: "No. If the Chain Event is canonical and Resolution cannot
complete, the Handle State is Failed."

Developer: "Do we need separate Handle States for MPC failure and validation
failure?"

Domain expert: "No. Keep the state as Failed and carry the reason or category
inside that variant."

Developer: "Should a temporary MPC outage immediately fail the Handle?"

Domain expert: "No. While retry policy still applies, the Handle remains
Pending. Failed means the Coprocessor has concluded the canonical Handle cannot
be materialized."

Developer: "Is MaterializationFailure only for Derived Handles?"

Domain expert: "No. MaterializationFailure applies to any Handle that cannot be
made Ready because packaging or binding SystemCiphertextV1 or its receipt
failed."

Developer: "Do we need separate states for waiting and running?"

Domain expert: "No. The domain state is Pending. Internal phases can explain
why it is pending without changing the Handle State vocabulary."

Developer: "Should the API return Pending for a Handle Key ingestion has not
seen?"

Domain expert: "No. Unknown Handle Keys are not Pending; normal API reads
return unknown."

Developer: "Is Materialization the same as Resolution?"

Domain expert: "No. Materialization is the binding step that makes a Handle
Ready. Resolution only applies to Derived Handles."

Developer: "Can Source Handles be materialized?"

Domain expert: "Yes. Materialization is the binding act for any Handle becoming
Ready, but only Derived Handles go through Resolution."

Developer: "Should the operation discriminant be called OperationType?"

Domain expert: "No. Use OperationCode to match the spec and avoid confusion
with HandleType."

Developer: "Is wrong arity a Lineage Violation?"

Domain expert: "No. Wrong arity is an Operation Violation: the operation exists,
but its operation rules are invalid."

Developer: "Should invalid operation arity be scheduled and fail later?"

Domain expert: "No. Detect Operation Violations during Chain Event Ingestion
when arity and HandleType facts are available, then mark the affected Derived
Handle as Failed."

Developer: "Can Select inputs be sorted like any other dependency set?"

Domain expert: "No. Select input order is semantic: predicate, when true, then
when false."

Developer: "Is a Handle Resolution Request the same as a Disclosure Request?"

Domain expert: "No. Disclosure Requests are user-facing Coordinator concerns.
Handle Resolution Requests are internal Coordinator-to-Coprocessor requests."

Developer: "Can a resolve request create a placeholder Handle Record?"

Domain expert: "No. Handle Records come from Chain Event Ingestion. Unknown
Handle Keys remain unknown."

Developer: "Can sym-client call the Internal Coordinator API?"

Domain expert: "No. sym-client talks to the Coordinator. The Coordinator talks
to the Coprocessor through the Internal Coordinator API."

Developer: "Does MPC decrypt the input for the host?"

Domain expert: "No. MPC performs To-Enclave Transformation and returns
EnclaveCiphertextV1. The host never receives plaintext."

Developer: "Should the Coprocessor perform To-Reader Transformation?"

Domain expert: "No. The Coordinator uses To-Reader Transformation after it gets
SystemCiphertextV1 for a Ready Handle."

Developer: "Can any enclave key receive transformed ciphertexts?"

Domain expert: "No. MPC requires Attestation that binds the key to an approved
Enclave Measurement."

Developer: "Can we treat AAD as display metadata?"

Domain expert: "No. AAD carries Ciphertext Binding and is part of the security
model."

Developer: "Can this handle be used in another domain?"

Domain expert: "Only if the protocol defines that. In this context, DomainId
scopes the Handle, Chain Event, and Ciphertext Binding."

Developer: "Where do we put lineage and the ChainEventRef?"

Domain expert: "Those belong to the Handle Record. They are durable facts about
the known Handle, not payloads of every Handle State variant."

Developer: "Is a Plaintext Handle private?"

Domain expert: "No. Plaintext Handle means the source value was public
plaintext on-chain, but the Handle still participates in the same symbolic
handle model."

Developer: "Did the host execute the operation?"

Domain expert: "No. The host scheduled Resolution. Enclave Execution is the
step that evaluates private values."

Developer: "Should we enqueue an execution task?"

Domain expert: "Queue a Resolution Task in the Coprocessor Host. Enclave
Execution is the private step inside that task."

Developer: "When can a Derived Handle be scheduled?"

Domain expert: "When it reaches Resolution Readiness: all ordered input Handles
are Ready and canonical."

Developer: "Should repeated requests start repeated work?"

Domain expert: "No. The Resolution Scheduler deduplicates work for the same
Handle and attaches callers to the current Handle State."

Developer: "Can the Coordinator ask the Coprocessor for ReaderCiphertextV1?"

Domain expert: "No. The Coprocessor returns SystemCiphertextV1 for a Ready
Handle. The Coordinator asks MPC to transform it to ReaderCiphertextV1."

Developer: "Should the Coprocessor register Readers?"

Domain expert: "No. Reader registration belongs to the Coordinator and MPC
flow, outside the Coprocessor."

Developer: "Is resolving a Handle the same as disclosing it?"

Domain expert: "No. Resolution prepares system-held encrypted state. Disclosure
delivers reader-targeted ciphertext through the Coordinator and MPC."

Developer: "Do we decode application calldata to find dependencies?"

Domain expert: "No. The Coprocessor reconstructs dependencies from the symVM
Event Surface."

Developer: "Should the Coprocessor read app contract state for disclosure
policy?"

Domain expert: "No. Disclosure policy belongs to the Coordinator. The
Coprocessor consumes the symVM Event Surface and chain metadata."

Developer: "How do we explain where this Handle Record came from?"

Domain expert: "Use its ChainEventRef. That points back to the consumed Chain
Event in the chain view."

Developer: "What happens if ingestion sees the same Chain Event twice?"

Domain expert: "Chain Event Ingestion is idempotent by ChainEventRef. The same
Chain Event must not create duplicate Handle Records."

Developer: "Which blocks should ingestion trust by default?"

Domain expert: "Use the `safe` Chain View by default, unless a deployment
chooses a stricter view such as `finalized`."

Developer: "Is reorg handling separate from ingestion?"

Domain expert: "No. Chain Event Ingestion owns canonicality handling, including
Orphan Discard."

Developer: "Did this handle fail because its block was orphaned?"

Domain expert: "No. Orphan Discard tombstones records from non-canonical Chain
Events. It is not a Failed Handle State."

Developer: "What should the Coordinator see for a tombstoned Handle Record?"

Domain expert: "Nothing in the normal handle API. Tombstoned records are not
Canonical Handle Records, so normal reads and resolution should treat them as
unknown."
