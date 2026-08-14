# Development Setup for Unattended Testing

**Date:** 2026-08-12
**Purpose:** what `mcxas` relies on, what this machine currently provides, and the
one-time setup that makes the full test matrix runnable with no interaction.

---

## 1. What the project relies on

### Build and unit tests (the hard requirements)

| Dependency | Why | Notes |
| --- | --- | --- |
| **Go 1.25+** | whole server | Pure-Go build: the SQLite driver is `modernc.org/sqlite` (no cgo) and the PostgreSQL driver is `pgx` (pure Go), so `go build` and `go test` need nothing beyond the toolchain |
| **Go module deps** | six direct | `huma/v2` (OpenAPI/REST), `chi/v5` (router), `google/uuid`, `prometheus/client_golang`, `yaml.v3`, `modernc.org/sqlite`; `pgx/v5` pulled for Postgres. All cached in the module cache after first download |
| **web/dist** | `web/embed.go` declares `//go:embed all:dist` | **Compile-time requirement.** Tracked in git deliberately, so a fresh clone builds without Node. Do not untrack it |

### Rebuilding the UI (only when web/src changes)

| Dependency | Why |
| --- | --- |
| **Node 20+ / npm** | Vite build of the React SPA (`make ui`); deps: react, react-router, recharts, lucide |

### Test-only, optional (tests skip or lose coverage without them)

| Dependency | What it unlocks | Behaviour when absent |
| --- | --- | --- |
| **PostgreSQL server binaries** | the entire Postgres store path: `s.q()` placeholder rewriting, dialect branches, `ON CONFLICT` behaviour | Currently **zero coverage** — the audit's biggest untested surface |
| **C compiler (gcc/mingw-w64)** | `go test -race` — the race detector needs cgo on Windows | Race detection impossible; concurrency fixes are inspection-verified only |
| **XSD validation** (`xmllint` or Python `lxml`) | CMS document schema validation test | Test **self-skips silently** — a green run does not mean schemas validated |
| `socat`, `nc` | `scripts/sip-smoke.sh` manual smoke script | Not part of automated testing; irrelevant here |

### Deployment-only (not needed for local testing)

`make install`, the systemd unit, and the service account are Linux-target concerns.

---

## 2. What this machine provides today

| Capability | State |
| --- | --- |
| Go 1.25.12 | ✅ `C:\Users\admin\sdk\go1.25.12` (user profile, checksum-verified) |
| Module cache | ✅ populated |
| Node / npm | ✅ v24.1.0 via nvm4w |
| `web/dist` | ✅ tracked |
| **PostgreSQL server** | ❌ **broken install.** `C:\Program Files\PostgreSQL\18` has `postgres.exe`, `initdb.exe` and client tools, but `share\` holds only `i18n` — no `postgres.bki`, no server support files. `initdb` fails immediately; the server cannot start. Effectively client-tools-only |
| C compiler | ✅ mingw-w64 gcc 16.2.0 (WinLibs, checksum-verified) at `%USERPROFILE%\sdk\mingw64\bin` — enables `go test -race` locally |
| Docker | ❌ not installed (use the Linux box for containers) |
| xmllint | ❌ not installed (CMS XSD test self-skips here; runs on the Linux box) |
| Python 3.13 + pip | ✅ (used by the harness fallback below) |

Put both toolchains on PATH for a shell session:
`set PATH=%USERPROFILE%\sdk\go1.25.12\bin;%USERPROFILE%\sdk\mingw64\bin;%PATH%`
Then `mingw32-make check` (build+vet+fmt+test) or `mingw32-make check-race`
(adds the race detector) runs the full local gate. Windows has no `make`;
mingw ships `mingw32-make`.

## 2a. Linux test box (NyxVectorTest, 172.25.221.105)

Debian 12.15, 6 vCPU, 8 GB RAM, ESXi guest — provisioned 2026-08-14 as the
unattended Linux test target. Keyed SSH only (dedicated ed25519 key
`~/.ssh/mcx-dev` on the dev machine, authorised for `nyx` and `root`; nyx is in
`sudo` and `docker`). Toolchain: Go 1.25.12 (checksum-verified, `/usr/local/go`),
docker.io, gcc 12, xmllint, git, rsync, build-essential.

**Verified matrix on this box (2026-08-14), repo at `5a9f3aa`:** build, vet,
`gofmt` clean; full suite passes; the XSD schema test **runs** (xmllint present)
instead of skipping; and `CGO_ENABLED=1 go test -race ./...` is **clean — zero
data races** across every package. The one race the detector found on its first
run (`sipTCPReadTimeout`, a test-mutated global) is fixed in `5a9f3aa`.

**Operational caveat — the network path, not the box.** A security appliance
sits between the dev machine's NAT'd egress (`172.16.99.171`) and the box's
subnet (`172.25.x`). It periodically resets SSH sessions and, after repeated
reconnects, temporarily blocks the source IP. The box itself is unaffected
(sshd 19h uptime through the "outages", no OOM). Two consequences for automation:

1. **Never stream large output over SSH, and never depend on a long-lived
   session.** Run heavy commands detached (`nohup … > /tmp/out.log 2>&1 &`) and
   fetch only small summaries. This is how the race result above was obtained
   after live sessions kept getting cut.
2. **Durable fix:** whitelist `172.16.99.171` on the appliance, or place the box
   on the same segment as the dev egress. Until then, expect intermittent
   session drops and back off (do not rapid-retry — that extends the block).

Do not reconfigure sshd on this box remotely without console standby: an early
attempt to harden it coincided with a path reset and looked like a lockout.

---

## 3. The plan

Two one-time actions for the operator; everything else is harness work in the repo
that runs unattended afterwards.

### Action 1 — repair PostgreSQL (operator, ~5 minutes, elevated)

Re-run the EDB installer (`C:\Program Files\PostgreSQL\18\installer\` or a fresh
download) and ensure the **"PostgreSQL Server"** component is selected — the
current installation is missing its data files, which no amount of configuration
fixes. The zip-archive binaries from enterprisedb.com extracted to
`C:\Users\admin\sdk\pgsql` work equally well and need no elevation.

**The Windows service is not required and should stay disabled.** The test
harness creates a throwaway cluster per run (`initdb` into %TEMP%, `pg_ctl start`
on a random port, drop at the end), which is faster, isolated, and leaves nothing
behind.

One caveat to verify after install: PostgreSQL refuses to run under a Windows
account holding administrative privileges. If this account is elevated,
`initdb` will say so explicitly — in that case create the standing service
instead (it runs under a virtual service account) and set
`MCXAS_TEST_PG_DSN` to point at it; the harness prefers the scratch cluster but
accepts a DSN.

### Action 2 — mingw-w64 for the race detector (delegable, no elevation)

The WinLibs mingw-w64 zip extracts into the user profile exactly like the Go
toolchain did — no admin, no registry, reversible by deleting the folder. With
`gcc` on PATH and `CGO_ENABLED=1`, `go test -race ./...` works natively.

This one is delegable: it can be downloaded, checksum-verified and extracted to
`C:\Users\admin\sdk\mingw64` without operator interaction, on request.

### Harness work in the repo (no operator action)

1. **PostgreSQL parity tests.** A `TestMain` helper in `internal/store/sqlite`
   that resolves, in order: `MCXAS_TEST_PG_DSN` if set → a scratch cluster via
   `initdb`/`pg_ctl` if server binaries are found (`MCXAS_TEST_PG_BIN` or the
   standard install path) → skip with a loud message. Every store test then runs
   twice, once per dialect. The moment Action 1 lands, Postgres coverage goes
   from zero to full parity with no further interaction.
2. **XSD validation without xmllint.** Extend the CMS schema test to fall back
   from `xmllint` to Python `lxml` (`pip install lxml`, wheels available for
   this interpreter). Removes the silent skip on this machine entirely.
3. **`make check`** — one target running `go build`, `go vet`, `gofmt -l` (fails
   on drift), and `go test ./...`; plus **`make check-race`** which adds
   `-race` when a C compiler is present and says clearly when it is not.
4. **A `-race`-aware CI note.** When a remote runner exists later, the same
   targets run there; nothing in the harness assumes this machine.

### What the matrix looks like once complete

| Layer | Trigger | Interaction needed |
| --- | --- | --- |
| build + vet + gofmt + unit/integration (SQLite) | `make check` | none (works today) |
| PostgreSQL parity | same run, auto-detected | none after Action 1 |
| XSD schema validation | same run, lxml fallback | none after `pip install lxml` (delegable) |
| race detector | `make check-race` | none after Action 2 |
| UI build | `make ui` (only when web/src changes) | none |

---

## 4. Explicitly out of scope

- **Docker** — nothing above needs it once mingw-w64 covers `-race`. It becomes
  interesting again for the FRMCS-phase interop testing (an IMS core in a
  container), not for unit testing.
- **A standing PostgreSQL service** — scratch clusters are strictly better for
  tests: no shared state, no port conflicts, no cleanup debt.
- **xmllint via MSYS2** — a whole POSIX environment for one binary; the lxml
  fallback is smaller and stays inside tooling already present.
