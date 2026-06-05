# Coprocessor

The Symbolic Execution Coprocessor is the off-chain private execution system
for `symVM`. It monitors handle events, reconstructs Handle Graph lineage,
schedules Resolution, calls MPC for ciphertext transformation, runs private
computation in the Enclave, and exposes materialized Handle State to the
Coordinator.

The sibling `../spec` repo is the protocol source of truth. Before changing
behavior, read the relevant spec files.

## Test

Run the Rust workspace test suite:

```sh
npm run test
```

Equivalent direct command:

```sh
cargo test --workspace
```

## Sandcastle

Sandcastle works GitHub issues labeled `Sandcastle` and `ready-for-agent`.
It plans open issues, creates per-issue branches, runs implementation agents,
reviews changes, opens PRs, and merges passing work.

Configure local credentials:

```sh
cp .sandcastle/.env.example .sandcastle/.env
```

Build the Sandcastle Docker image:

```sh
docker build \
  --build-arg AGENT_UID=$(id -u) \
  --build-arg AGENT_GID=$(id -g) \
  -t sandcastle:coprocessor \
  -f .sandcastle/Dockerfile \
  .
```

Check configuration:

```sh
npm run sandcastle -- --check-config
```

Run Sandcastle:

```sh
npm run sandcastle
```
