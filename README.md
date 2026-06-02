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
npx sandcastle docker build-image \
  --image-name sandcastle:coprocessor \
  --dockerfile .sandcastle/Dockerfile
```

Check configuration:

```sh
npm run sandcastle -- --check-config
```

Run Sandcastle:

```sh
npm run sandcastle
```
