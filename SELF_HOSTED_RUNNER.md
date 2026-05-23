# Self-Hosted Runner

This repo can run the Build workflow on a local Docker Compose based GitHub Actions runner.

Default labels:

```text
self-hosted, linux, x64, mihomo-local
```

Start the runner:

```bash
RUNNER_TOKEN=$(gh api -X POST repos/H5Z2P5Z2P/mihomo/actions/runners/registration-token --jq .token) \
  docker compose -f docker-compose.runner.yml up -d --build
```

Run the workflow manually on the self-hosted runner:

```bash
gh workflow run Build -r anyreality-snell-alpha \
  -f version=v1.19.25-alpha-YYYYMMDDHHMM-anyreality-snell-alpha \
  -f runner=self-hosted \
  -f smoke=false
```

Run the workflow manually on GitHub-hosted runners:

```bash
gh workflow run Build -r anyreality-snell-alpha \
  -f version=v1.19.25-alpha-YYYYMMDDHHMM-anyreality-snell-alpha \
  -f runner=github-hosted \
  -f smoke=false
```

For push/tag-triggered releases, the workflow uses GitHub-hosted runners. A rerun of an old failed tag workflow still uses the workflow file stored at that old tag.

When `runner=self-hosted` is selected, `actions/setup-go` cache upload is disabled. Go module/build caches are kept locally through Docker volumes.

Check runner status:

```bash
gh api repos/H5Z2P5Z2P/mihomo/actions/runners --jq '.runners[] | select(.name == "mihomo-local") | {name,status,busy,labels:[.labels[].name]}'
```

Stop the runner:

```bash
docker compose -f docker-compose.runner.yml down
```
