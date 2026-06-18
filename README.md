# VectorCore MCX

`mcxas` is a Go-based MCX IMS Application Server targeting MCOP SDK 3.0 and
3GPP Release 13 MCPTT interoperability. It combines SIP call control,
CMS/GMS XCAP services, MCPTT media observation and relay, persistence, and an
OAM REST API/UI in one binary.

> **Note:** This project is a work in progress. A fully working implementation
> should not be expected yet.

## Requirements

- Go 1.25 or newer
- Node.js and npm (to build the embedded React UI)
- `make`

The optional SIP smoke test also requires `nc` and `socat`.

## Build and test

```sh
make
make test
```

`make` runs the UI build and then builds `bin/mcxas`. To rebuild only the Go
binary while retaining the existing `web/dist` assets, run `make build`.

For UI development, start the API separately and run:

```sh
make dev-ui
```

The Vite development server proxies `/api`, `/metrics`, and `/health` to
`localhost:8080`.

## Configure and run

Edit `config.yaml` for the deployment network before starting the server. The
checked-in file contains lab-specific advertised addresses and MCX identities.

```sh
./bin/mcxas -c config.yaml
```

Command-line flags:

- `-c <path>` selects the YAML configuration file (default `config.yaml`).
- `-d` enables debug-level logging, overriding `log.level`.
- `-v` prints the application version and exits.

If the selected configuration file does not exist, built-in defaults are used.
Invalid or unreadable configuration files cause startup to fail.

### Listeners and defaults

| Service | Configuration | Default |
| --- | --- | --- |
| OAM API/UI | `api.listen` | `:8080` |
| CMS/XCAP | `cms.listen` | `:8100` |
| SIP UDP | `sip.udp_listen` | `:5060` |
| SIP TCP | `sip.tcp_listen` | `:5060` |
| RTP UDP | `media.listen_host` + `media.audio_port` | `0.0.0.0:40000` |
| RTCP UDP | `media.listen_host` + `media.rtcp_port` | `0.0.0.0:40001` |
| MCPTT floor control UDP | `media.listen_host` + `media.floor_control_port` | `0.0.0.0:40002` |

Important configuration behavior:

- `sip.advertise_host`, `sip.advertise_port`, and `sip.transport` form the
  advertised SIP Contact and Record-Route URIs.
- `sip.record_route` defaults to `true`.
- `sip.notify_route_set_order` defaults to `preserve`, which retains the
  learned IMS route order for in-dialog NOTIFY requests.
- `sip.options.enabled` enables periodic outbound OPTIONS on learned SIP
  routes; `sip.options.interval` defaults to `30s`.
- `cms.enabled` controls the XCAP server. `cms.xcap_root` is derived from the
  advertised SIP host and CMS port when omitted.
- `media.enabled` controls all three media listeners.
- `media.advertise_host` defaults to `sip.advertise_host`.
- `media.direction` defaults to `sendrecv`.
- `media.floor_auto_grant` enables floor grant, deny, idle, and queue-position
  responses. The grant duration defaults to 30 seconds.
- `media.log_packets` enables sampled packet logging, controlled by
  `media.log_packet_interval`.
- `database.driver` accepts `sqlite`, `postgres`, or `postgresql`.
- `database.dsn` defaults to `mcxas.db`.
- `log.file` defaults to `mcxas.log`; `log.level` accepts `debug`, `info`,
  `warn`, or `error`.
- IMS realm and MCX identities/endpoints are derived from `ims.mcc`,
  `ims.mnc`, and the advertised host when their explicit values are omitted.

## OAM endpoints

- UI: `http://127.0.0.1:8080/ui/`
- API documentation: `http://127.0.0.1:8080/api/v1/docs`
- OpenAPI document: `http://127.0.0.1:8080/api/v1/openapi.json`
- Health check: `http://127.0.0.1:8080/health`
- Prometheus metrics: `http://127.0.0.1:8080/metrics`
- XCAP root: `http://127.0.0.1:8100/xcap-root/`

The REST API provides status and CRUD operations for users, groups, static
memberships, and runtime affiliations, plus read-only registration, call, and
SIP dialog views under `/api/v1`.

The UI exposes dashboards for users, groups, memberships/affiliations,
registrations, and calls.

## Current implementation

SIP signaling:

- UDP and TCP listeners
- inbound and optional periodic outbound `OPTIONS`
- `PUBLISH` for `poc-settings` and presence-based group affiliation
- `SUBSCRIBE` for `presence` and `xcap-diff`, with initial in-dialog `NOTIFY`
- third-party `REGISTER` and de-registration tracking with automatic expiry
- `INVITE`, `ACK`, `BYE`, and RFC 3261 cancellation handling
- in-dialog `UPDATE` and `INFO`
- multipart MCPTT-info and SDP extraction
- Record-Route/Contact construction and persisted dialog route state
- group-call membership admission and outbound INVITE/BYE legs to other
  registered group members

CMS/GMS and identity:

- XCAP `GET`, `PUT`, and `DELETE`
- generated Release 13 UE initial configuration, UE configuration, MCPTT user
  profile, service configuration, and OMA group documents
- content ETags and xcap-diff document notifications
- development IdMS authorize/token callback shim at `/idms/*`

The IdMS shim issues unsigned development JWTs and is not a production
authentication service.

Media and floor control:

- SDP answers advertising RTP, RTCP, and MCPTT floor-control ports
- RTP/RTCP/floor packet matching to active calls
- RTP packet, loss, jitter, byte, and rejected-packet accounting
- RTP relay between active legs of the same group call
- MCPTT floor request/grant/deny/release/idle and queue-position handling
- single-holder enforcement and rejection of RTP from a non-holder SSRC
- implicit floor grant through the SDP answer for the current MCOP client flow

Persistence supports SQLite and PostgreSQL for users, groups, memberships,
affiliations, CMS documents, publications, subscriptions, dialogs,
registrations, and calls.

## Smoke test

With `mcxas` running, exercise TCP/UDP OPTIONS plus sample multipart PUBLISH
and INVITE requests:

```sh
./scripts/sip-smoke.sh [host] [port] [ims-realm]
```

Defaults are `127.0.0.1`, `5060`, and
`ims.mnc435.mcc311.3gppnetwork.org`.

## Installation

```sh
sudo make install
```

This installs the binary under `/opt/vectorcore`, copies the initial
configuration to `/opt/vectorcore/etc/mcxas.yaml` if it does not already
exist, and enables and starts `vectorcore-mcxas.service`. Build the UI with
`make ui` before installation if `web/dist` is not already present.
