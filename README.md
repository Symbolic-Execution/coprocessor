## Coprocessor

### Test

```sh
npm run test
```

### Sandcastle

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
