# openvasconf

`openvasconf` keeps customer network definitions and their Greenbone/OpenVAS scan objects in sync. It accepts IPv4 addresses and CIDRs, adds `/32` to bare addresses, separates RFC1918 space from public WAN space, splits broad networks into `/24` entries, and packs entries into targets containing at most 4,095 addresses.

The database keeps hosts in canonical `/32` form. GMP receives single hosts as bare IPv4 addresses because current gvmd releases reject a `/32` suffix in target host specifications.

For each customer it manages:

- one persistent weekly schedule, randomly assigned Monday–Thursday between 07:00 and 15:00;
- `Customer_PrivateIP_TargetN` / `Customer_PrivateIP_TaskN` objects;
- `Customer_WAN_TargetN` / `Customer_WAN_TaskN` objects;
- a durable local mapping and ownership marker for safe, idempotent updates.

Removing a network or customer soft-deletes it locally and moves only resources owned by this installation to Greenbone trash. It never permanently purges Greenbone objects.

## Requirements

- Docker Engine with Compose v2
- 4 CPU cores, 8 GB RAM, and 60 GB free storage recommended for the Greenbone test stack
- access from the scanner containers to the networks you intend to scan

Greenbone describes its Community Container setup as a testing and familiarization environment, not a production deployment.

## Test deployment beside Greenbone

The project deliberately does not vendor Greenbone's Compose file because Greenbone asks users to obtain its latest revision. From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Force deploy, secrets | Out-Null
Invoke-WebRequest `
  -Uri https://greenbone.github.io/docs/latest/_static/compose.yaml `
  -OutFile deploy/greenbone-compose.yaml

Set-Content -NoNewline secrets/admin_password '<strong-openvasconf-password>'
Set-Content -NoNewline secrets/gmp_password '<strong-greenbone-password>'
```

Start Greenbone first, then replace its insecure initial `admin` password with the exact value stored in `secrets/gmp_password`:

```powershell
docker compose -f deploy/greenbone-compose.yaml up -d
docker compose -f deploy/greenbone-compose.yaml exec -u gvmd gvmd `
  gvmd --user=admin --new-password='<strong-greenbone-password>'
```

Feed loading can take a while. Build and start the orchestrator with the overlay:

```powershell
docker compose `
  -f deploy/greenbone-compose.yaml `
  -f deploy/compose.greenbone.yaml `
  up -d --build openvasconf
```

The interfaces bind only to localhost:

- openvasconf: <http://127.0.0.1:8080>
- Greenbone Security Assistant: <https://127.0.0.1:9392>

Log in to openvasconf as `admin` with `secrets/admin_password`. On first successful Greenbone connection, the service selects `OpenVAS Default`, `Full and fast`, and `All IANA assigned TCP` by exact name. Review them under **Settings**; a customer may override any of them.

For `testcomp1` with:

```text
10.1.0.0/16
192.168.10.0
7.7.7.7/32
```

the preview and reconciler produce 18 private target/task pairs and one WAN pair. The `/16` becomes 256 `/24` entries. Each target stays below the hard 4,095-address limit.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `OPENVASCONF_LISTEN` | `127.0.0.1:8080` | HTTP listen address |
| `OPENVASCONF_DATABASE` | `data/openvasconf.db` | SQLite database path |
| `OPENVASCONF_GMP_SOCKET` | `/run/gvmd/gvmd.sock` | gvmd Unix socket |
| `OPENVASCONF_GMP_USERNAME` | `admin` | GMP user |
| `OPENVASCONF_GMP_PASSWORD_FILE` | — | File containing the GMP password |
| `OPENVASCONF_ADMIN_PASSWORD_FILE` | — | File used to bootstrap the local admin |
| `OPENVASCONF_TIMEZONE` | `Europe/Vienna` | Default schedule timezone |
| `OPENVASCONF_RECONCILE_INTERVAL` | `1m` | Drift-reconciliation interval |
| `OPENVASCONF_EXTERNAL_TIMEOUT` | `15s` | Per-GMP-call deadline |
| `OPENVASCONF_SESSION_LIFETIME` | `12h` | Local admin session lifetime |
| `OPENVASCONF_SECURE_COOKIES` | `false` | Require HTTPS-only session cookies |

Direct password environment variables exist as a development fallback, but Docker secrets are preferred. The local admin secret is read only when the admin account is first created; replacing that file does not silently replace an existing password.

## Operations

Trigger **Synchronize now** after feeds have loaded or wait for the periodic reconciler. A customer remains `pending` or `error` until every desired object has been checkpointed. Repeating synchronization with unchanged input performs no Greenbone writes.

The operator console also provides:

- search, state filters, sorting, compact view, per-customer sync/retry, and bulk sync;
- editable weekly slots, exact next-run dates, global schedule defaults, and explicit schedule randomization;
- duplicate/overlap warnings, canonical `/32` handling, unique-IP totals, and 4,095-IP target utilization;
- a mandatory signed before/after review before normal UI creates or edits are applied;
- customer cloning, descriptions, tags, timestamps, reconciliation progress, and per-operation history;
- versioned JSON export plus validated preview-before-apply import; omitted customers are not deleted;
- live GMP latency, feed version/age, active task state, latest severity, ownership-checked scan start, and remote drift inspection.

Existing customer schedules are intentionally preserved when the global allowed days or hours change. The UI warns when a retained slot sits outside the current defaults; use **Randomize schedule** to assign a new compliant slot.

Greenbone does not allow host or port-list changes on a target while a task references it, and scheduled task policy fields are not reliably mutable. For those changes, reconciliation moves the owned task to trash, updates the retained target when needed, and creates a replacement task with the same deterministic name and schedule. Historical task data remains recoverable in Greenbone trash.

Useful diagnostics:

```powershell
docker compose -f deploy/greenbone-compose.yaml -f deploy/compose.greenbone.yaml logs openvasconf
docker compose -f deploy/greenbone-compose.yaml logs gvmd
docker compose -f deploy/greenbone-compose.yaml run --rm gvm-tools `
  gvm-cli socket --xml '<get_version/>'
```

Common failures:

- **GMP socket unavailable:** gvmd is still starting, the named volume is not shared, or socket ownership differs from GID 1001. Check `stat /run/gvmd/gvmd.sock` from `gvm-tools` and set the overlay's `group_add` to that GID.
- **Greenbone options unavailable:** feeds have not finished importing their scanner, config, and port-list objects.
- **Ownership mismatch:** a mapped remote object no longer has this installation's marker. The service stops rather than modify or delete a foreign object.
- **Authentication failed:** make `secrets/gmp_password` match the password configured with `gvmd --new-password` and recreate the app container.

Back up the SQLite volume before upgrades:

```powershell
docker run --rm `
  -v greenbone-community-edition_openvasconf_data:/source:ro `
  -v ${PWD}:/backup `
  alpine:3.22 tar czf /backup/openvasconf-data.tgz -C /source .
```

Restore into a stopped, empty `openvasconf_data` volume. SQLite contains the installation ID and Greenbone ownership mappings; losing it means the service will intentionally refuse to assume ownership of existing objects.

Stop the test environment while retaining all data:

```powershell
docker compose -f deploy/greenbone-compose.yaml -f deploy/compose.greenbone.yaml down
```

Adding `--volumes` permanently removes the Greenbone feeds/databases and openvasconf database; use it only when you explicitly want a clean test environment.

## Verified integration environment

Live integration was verified on 2026-08-20 with Docker 29.7.2, gvmd 26.36.1, GMP 22.7, and Greenbone feed release 24.10 using Greenbone's current official community-container Compose file. The Greenbone documentation URL retains the `22.4` path while its `latest` stack currently serves these newer component versions.

## Development verification

```powershell
gofmt -w (rg --files -g '*.go')
go vet ./...
go test ./...
go test -race ./...
docker build -t openvasconf:test .
docker compose -f deploy/greenbone-compose.yaml -f deploy/compose.greenbone.yaml config
```

The container build keeps `internal/web/static/app.js` readable in the source
tree. A pinned esbuild release minifies it in an isolated Node build stage, and
only the minified file is copied into the Go embed path. Node, npm,
`node_modules`, source maps, and the readable JavaScript source are absent from
the runtime image. Reproduce the asset locally with:

```powershell
$env:npm_config_cache = Join-Path $PWD '.cache\npm'
npm ci --no-audit --no-fund
npm run build:assets
node scripts/check-npm-licenses.mjs
```

## GitHub automation and supply chain

The repository includes five fail-closed workflows:

- **CI** checks formatting, vet, golangci-lint, shuffled/repeated/race tests,
  coverage, deterministic minification, and the final runtime image.
- **Security** runs gosec, govulncheck, CodeQL, dependency review, Hadolint,
  and Trivy filesystem/image scans. SARIF and reports are retained even when a
  scanner reports a failure.
- **Supply chain** verifies module tidiness, applies explicit Go and npm license
  allowlists, audits workflow syntax/security, and publishes OpenSSF Scorecard
  results.
- **Publish container** creates `linux/amd64` and `linux/arm64` GHCR images with
  BuildKit SPDX SBOM and maximum provenance, a GitHub artifact attestation, and
  a keyless Cosign signature.
- **Weekly deep scan** repeats race, vulnerability, and fresh-image scanning at
  03:17 UTC every Monday and also supports manual dispatch.

All third-party actions are pinned to full commit SHAs. Dependabot checks Go,
npm, Docker, and GitHub Actions weekly and groups related updates.

Publishing uses these tags:

- the default branch publishes `edge` and `sha-<full-commit>`;
- `v1.2.3` publishes `1.2.3`, `1.2`, `1`, `latest`, and the immutable SHA tag;
- pull requests only validate and never log in, publish, sign, or attest.

Use the digest emitted as the `image-digest` workflow artifact for deployment.
For an image stored as `ghcr.io/OWNER/REPOSITORY`, verification is:

```powershell
$image = 'ghcr.io/OWNER/REPOSITORY@sha256:DIGEST'
cosign verify `
  --certificate-identity-regexp '^https://github.com/OWNER/REPOSITORY/.github/workflows/container.yml@refs/(heads|tags)/.+$' `
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' `
  $image
gh attestation verify $image --repo OWNER/REPOSITORY
docker buildx imagetools inspect $image
```

Before enabling required checks, configure the GitHub repository with Actions
enabled, read/write workflow access for `GITHUB_TOKEN`, GHCR package publishing,
the dependency graph, Dependabot alerts and security updates, code scanning,
private vulnerability reporting, and branch protection for `main`. Require the
CI, Security, and Supply chain checks and block force pushes. Public repositories
can publish Scorecard results directly; private repositories need GitHub Advanced
Security for the CodeQL, SARIF, dependency-review, and Scorecard integrations.

The workflows never use Greenbone credentials or contact the live GMP socket.
Local scanner equivalents are:

```powershell
go install github.com/securego/gosec/v2/cmd/gosec@v2.28.0
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
go install github.com/google/go-licenses/v2@v2.0.1
gosec ./...
govulncheck ./...
go-licenses check --ignore openvasconf `
  --allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC,MPL-2.0 ./...
```
