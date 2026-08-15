# VectorCore MCX — MCX Compliance Plan, with FRMCS Behind a Config Flag

**Date:** 2026-08-12
**Basis:** [MCX-FRMCS-AUDIT-2026-08-12.md](MCX-FRMCS-AUDIT-2026-08-12.md) and
[AUDIT-2026-08-11.md](AUDIT-2026-08-11.md)
**Goal:** bring `mcxas` to 3GPP MCX conformance as the base behaviour, then add FRMCS as an
opt-in profile selected by a single configuration flag.

---

## 1. The governing principle

> **The base build is a conformant 3GPP MCX server. FRMCS is a profile applied on top: it
> *narrows* what the base permits and *adds* railway semantics. It never forks the base.**

This is not just tidiness. It falls out of what the audit found: **most of what FRMCS needs is
ordinary MCX**. Functional alias, ad hoc group calls, multi-talker floor control, MCData SDS —
all four are standard Rel-19 MC features that FRMCS happens to lean on heavily. Only the railway
*semantics* layered over them are genuinely FRMCS-specific.

Concretely, roughly 80% of the FRMCS work is MCX work you need anyway. That is why MCX-first is
the correct order, and why the flag stays small.

## 2. Decisions taken, with rationale

These are calls I am making so the plan is actionable. Each is reversible; §8 lists the ones
worth your explicit confirmation.

**Target Release 19, not 18.** ETSI TS 103 765-2 clause 4.1 says MCX "from 3GPP Release 18
onwards", so Rel-19 is permitted. Rel-19 is the newest stable set in your library, and I verified
Rel-20 adds no clauses to 24.379, 24.380 or 23.283 — so Rel-19 will not be overtaken mid-project.
The one caution: FRMCS pins *specific Rel-18 document versions* as normative references, so where
Rel-19 changed a behaviour relative to Rel-18, the Rel-18 reading wins for FRMCS-profiled
deployments. Expect one or two such cases; treat them as profile-gated.

**MCOP SDK 3.0 compatibility is not a constraint** (confirmed 2026-08-12). The target client is
either purpose-built or off-the-shelf. This *reduces* Phase 2 rather than complicating it: a set
of MCOP-specific workarounds currently in the code become deletions instead of constraints to
preserve (see Phase 2). It also means the definition of "working" shifts from "the MCOP demo
still runs" to conformance against the spec — see the client and test strategy at the end of §6.

**Base stays unflagged and conformant.** No `if frmcs` inside call control, floor control, or
XCAP. The flag resolves once at startup into a profile object; behaviour differences go through a
small interface (§5).

**SIP posture is migrated in stages, not ripped out.** FRMCS requires the server to be an
Application Server behind a SIP core (TS 103 765-2 clause 5.1.2, on SIP-2/ISC). Today it is a
fused SIP endpoint that terminates REGISTER itself. Ripping that out immediately breaks the only
working demo, so add `sip.mode: standalone | application_server`, keep `standalone` working
during the transition, and **delete it once an IMS core is in the lab.** This is a migration aid
with an explicit removal criterion, not a permanent second mode.

**MCVideo is out of scope entirely.** FRMCS does not mandate it (AT-7800 clause 9.2.3: "MCVideo
is not in scope") and it is not on the P25 path. Noted only because generalising the RTCP-APP
codec in Phase 2d makes it cheap later if that changes.

## 3. What is base, and what is behind the flag

This split is the core of the design. Get it right and the flag stays a thin policy layer.

| Capability | Spec | Where it lives |
| --- | --- | --- |
| Functional alias: activate/deactivate/take-over/interrogate/notify | 24.379 clause 9A | **Base** |
| Ad hoc group call: setup, release, rejoin, modify participants | 24.379 clause 17 | **Base** |
| Ad hoc group emergency alert | 24.379 clause 12.1A | **Base** |
| Multi-talker floor control, TLV parsing, timers, state machine | 24.380 | **Base** |
| Interconnection roles: controlling / participating / non-controlling | 24.379 | **Base** |
| Emergency, imminent peril, Resource-Priority (RFC 8101) | 24.379 clause 6.2.8 | **Base** |
| Location reporting config / request / report | 24.379 clause 13.2, 13.3 | **Base** |
| XCAP write model, node selectors, conditional requests | 24.481 / 24.484 / RFC 4825 | **Base** |
| Identity management, token validation, TLS, SRTP | 24.482 / 33.180 | **Base** |
| MCData SDS, then IPcon | 24.282 / 24.582 | **Base** (FRMCS mandates it; the service itself is standard) |
| — | | |
| Restrict permitted sessions to ad hoc group call + emergency alert | TS 103 765-2 clause 5.1.1 | **Flag** |
| FA label structure `loc.ident.equip.func@org`, `###` wildcards | AT-7800 clause 11.6.2.3-.2.4 | **Flag** |
| FA-addressed private call promoted to ad hoc group call | AT-7800 Figure 11-6 | **Flag** |
| `<call-participants-criterias>` parsing and evaluation | FIS-7970 clause 4.3.6.10 | **Flag** |
| Geographic participant determination, polygons, continuous re-evaluation | FIS-7970 Table 2; FRS clause 11.1.4.2i | **Flag** |
| Railway priority A-G, 6-digit `<user-requested-priority>`, force RP "Normal" | FRS Appendix J; TS 103 765-2 clause 6.2.5 | **Flag** |
| Railway floor priority policy, dispatcher pre-emption | FIS-7970 clause 4.3.8; FRS clause 8.2.3 | **Flag** |
| REC alert / voice / data coupling | FRS clause 10.11 | **Flag** |

Read the right-hand column as the test of whether the split is holding: if something railway-shaped
starts creeping into the base, or something generic ends up behind the flag, the design has drifted.

## 4. The configuration flag

Follows the existing `cms:` / `media:` idiom — a top-level section with `enabled:`, snake_case
keys, durations as quoted strings. Validated against the real `config/config.yaml`: it parses,
merges without clobbering any existing section, and defaults to disabled.

```yaml
# FRMCS (Future Railway Mobile Communication System) profile.
#
# The base server targets 3GPP Release 19 MCX and is conformant with this
# section disabled. Enabling it applies the ETSI TS 103 765-2 profile, which
# both RESTRICTS MCPTT (clause 5.1.1: ad hoc group call and emergency alert
# only) and ADDS the railway behaviour configured below.
frmcs:
  enabled: false

  # Railway operator organisation code. Forms the @-suffix of functional
  # aliases: <location>.<identification>.<equipment>.<function>@<org_code>
  # (UIC AT-7800 clause 11.6.2.3). Required when enabled.
  organisation_code: "example-ru.eu"

  # Enforce the TS 103 765-2 clause 5.1.1 service profile. Leave true for
  # conformance; set false only for mixed-mode lab work where prearranged
  # and chat group calls must remain reachable alongside FRMCS ad hoc calls.
  restrict_to_adhoc: true

  # Server-side participant determination from the <call-participants-criterias>
  # list carried in the INVITE mcptt-info body (UIC FIS-7970 clause 4.3.6.10).
  participant_determination:
    enabled: true
    # Safety margin applied when matching users to an addressed area. FRS
    # clause 10.11 requires a margin; the value itself is operator policy.
    area_safety_margin_m: 500
    # Re-evaluate eligibility for the life of the call and drop users who
    # leave the addressed area (FRS clause 11.1.4.2i).
    continuous_reevaluation: true
    reevaluation_interval: "10s"

  # Railway priority. FRS Appendix J defines seven levels A-G, signalled as the
  # 6-digit <user-requested-priority> [category(4)][sub-category(2)]
  # (TS 103 765-2 clause 6.2.5).
  priority:
    enabled: true
    # TS 103 765-2 clause 6.2.5 requires Resource-Priority to always be
    # "Normal" on the SIP INVITE. Disable only for interop debugging.
    force_resource_priority_normal: true

  # Multi-talker floor control (FRS clause 8.2.3, TS 24.380 clause 4.1.1.2).
  # The FRMCS floor priority scheme is still an editor's note in AT-7800
  # clause 21.2.6, so this is local policy and is expected to change.
  floor:
    max_simultaneous_talkers: 2
    dispatcher_preemptive: true

  # Railway Emergency Communication. An REC-alert is always set up first and
  # may be followed by REC-voice and/or REC-data legs (FRS clause 10.11).
  rec:
    enabled: true
    # Couple REC-voice setup to the preceding REC-alert rather than treating
    # it as an independent call.
    couple_voice_to_alert: true
```

**Validation rules to enforce at load** (the audit found `config.go` has no validation function at
all, so this arrives with the general validation work in Phase 0):

- `frmcs.enabled: true` requires a non-empty `organisation_code`.
- `frmcs.enabled: true` requires the base features it depends on to be present — reject at startup
  rather than failing at call time if functional alias or ad hoc group support is not compiled in.
- `restrict_to_adhoc: false` and `force_resource_priority_normal: false` are non-conformant; log a
  warning at startup naming the clause each one violates.
- `max_simultaneous_talkers` must be >= 1; a value of 1 disables multi-talker without a separate
  flag.
- `frmcs.enabled: false` must leave every code path byte-identical to a build with no FRMCS support.

## 5. The code seam

One small interface, resolved once at startup. The FRMCS implementation embeds the MCX one and
overrides only what it must, so the base stays authoritative.

```go
// internal/profile/profile.go

// Profile encapsulates the behavioural differences between a plain 3GPP MCX
// deployment and one operating under a vertical profile such as FRMCS.
// The base MCX implementation is conformant on its own; a Profile may narrow
// what is permitted and supply domain-specific resolution logic.
type Profile interface {
	Name() string

	// SessionPermitted reports whether a session type may be established.
	// FRMCS restricts this to ad hoc group calls (TS 103 765-2 clause 5.1.1).
	SessionPermitted(sessionType SessionType) error

	// ResolveAddressed expands an addressed identity into concrete MC service
	// IDs. FRMCS applies functional-alias label matching and "###" wildcards.
	ResolveAddressed(ctx context.Context, addressed string) ([]MCServiceID, error)

	// DetermineParticipants selects the members of an ad hoc group call. Base
	// MCX uses the supplied resource list; FRMCS evaluates the FIS-7970
	// <call-participants-criterias> against location, route and role.
	DetermineParticipants(ctx context.Context, req CallRequest) ([]Participant, error)

	// EffectivePriority derives call priority. FRMCS maps the 6-digit
	// <user-requested-priority> onto the A-G ordering of FRS Appendix J.
	EffectivePriority(req CallRequest) (Priority, error)

	// FloorPolicy supplies arbitration policy for a group: simultaneous-talker
	// limit and per-user pre-emption rules.
	FloorPolicy(ctx context.Context, groupID string) (FloorPolicy, error)
}
```

Six hook points, matching the six rows in the flag column of §3 that are behavioural rather than
purely representational. `profile.MCX` is the default; `profile.FRMCS` embeds it. Anything FRMCS
does not override falls through to conformant MCX behaviour by construction.

This seam is also where a P25 IWF profile would attach later — see §7.

## 6. Phases

Execute one phase at a time and confirm before moving on. Exit criteria are stated so "done" is
not a judgement call.

### Phase 0 — Foundation (no spec work) — COMPLETE 2026-08-12

Delivered across twelve commits. Suite went from one failing test to 97 passing,
with `go build`, `go vet` and `gofmt` all clean. Two items were deliberately
carried forward, both recorded below and in the commits that defer them:

- **`go test -race` has never been run.** This machine has `CGO_ENABLED=0` and no
  C toolchain, which the Windows race detector requires. Run it in a container
  before trusting the concurrency work:
  `docker run --rm -v B:\vectorcore-mcx:/src -w /src golang:1.25 go test ./... -race`
- **Client transaction state machines and outbound retransmission (Timers A/E)
  are not implemented.** Only the server half of the transaction layer landed.
  The client half is exercised by the server-to-server work, so it belongs with
  Phase 2a rather than here.

Original scope, for reference:

Everything in [AUDIT-2026-08-11.md](AUDIT-2026-08-11.md) that is prerequisite to touching the
protocol layers: `.gitignore` plus purge of the committed binary and 8,629 `node_modules` files;
remove the committed lab identifiers and the DSN password; systemd hardening (`User=`,
`ProtectSystem`, `NoNewPrivileges`); SIP input size caps, TCP read deadlines, bounded goroutines;
store transactions on floor grant and membership mutation, the missing indexes, and the
RFC3339Nano lexicographic expiry bug; a real config validation function.

Then the single largest foundational item: **a SIP transaction layer** — branch matching, RFC 3261
timers, retransmission handling, and duplicate suppression. Nothing above it is trustworthy
without this.

*Exit:* `go test ./... -race` green; no secrets in git history going forward; a duplicated INVITE
no longer re-runs call setup.

### Phase 1 — Security plane — DELIVERED 2026-08-12, except key management

Four commits. The exit criteria read against reality:

- **Shim gated:** `idms.development_shim_enabled` defaults false; endpoints
  unregistered when off; tokens signed ES256 with a published JWKS; open
  redirect closed. Still not a TS 24.482 IdMS and not intended to be.
- **No unsigned token accepted:** the only token consumer (service
  authorization) accepts ES256 only and fails closed when its keys are
  missing.
- **TLS:** every listener can now serve TLS (OAM, CMS/XCAP, SIP), outbound
  SIP dials TLS with mandatory peer verification, and derived URLs follow
  the scheme. **Plaintext remains the default**, deliberately: flipping the
  default would brick bring-up with no certificates present. Enabling TLS is
  a deployment decision, one section in config.yaml.
- **Service authorization:** opt-in via sip.auth.require_service_authorization;
  emits the first TS 24.379 Warning text (101).
- **Carried forward: KMS integration and SRTP/SRTCP.** Phase-sized on its
  own (MIKEY-SAKKE, GMK/PCK/CSK distribution, SRTP key derivation). Nothing
  in Phases 2-3 depends on it; it must land before any deployment where the
  media path crosses an untrusted network.

Original scope, for reference:

TLS on every listener. Decide the IdMS question: either implement 24.482 properly, or hard-disable
the shim behind explicit config and validate real signed tokens from an external IdMS. Either way
the `alg:none` path goes. Add access-token validation on the service-authorization PUBLISH
(33.180 clause 5.1.3.2.3). KMS integration and SRTP/SRTCP can be staged behind this but must not
be deferred indefinitely — FRMCS assumes them.

*Exit:* no plaintext interface; no unsigned token accepted anywhere; the shim cannot be reached
without an explicit config opt-in.

### Phase 2 — MCX service conformance core

The compounding four, in dependency order. This is the bulk of the project.

**2.0 — first, delete the MCOP accommodations.** With MCOP compatibility dropped, several
non-conformant behaviours the audit flagged exist only to satisfy that client and can simply go,
rather than needing a compatibility shim: the hardcoded `Answer-Mode: Auto` on outbound INVITEs
(sip.go:1057), which currently defeats commencement-mode semantics for every call type; the
literal Doubango-tuned multipart INVITE body (sip.go:973-1013); the unconditional
`mc_granted;mc_implicit_request` in the SDP answer (sip.go:1758), which violates the conditionality
of 24.380 clause 6.4; and the outbound INVITE omitting the floor-control `m=` line. Do these first
so the conformant implementations in 2a-2d are not built on top of them.

**Phase 2a status: COMPLETE 2026-08-15.** All six slices of
DESIGN-2A-INTERCONNECTION-ROLES.md delivered: client transactions (f2f47aa),
role extraction with pinned wire behaviour (e5593c9), controlling-function
conformance - affiliation admission, invite-before-answer ordering, session
identity with isfocus, warning texts (8b8ec80), participating-function
conformance - served-user check, answer-mode from published poc-settings
(8244112), remote controlling binding over SIP with sip.remote_groups
(e8fdea9), and sip.mode application_server with third-party REGISTER binding
per clause 7.3.2. Deferred with clauses cited in the commits: TNG1/TNG3
timers, RFC 4028 session supervision, media anchoring for relayed sessions,
CANCEL relay, multiple-bindings/multiple-devices-ind.

**2a. Interconnection roles** — controlling / participating / non-controlling. Prerequisite for
IWF, GSM-R interworking, FRMCS interconnection and regroup. Also where `sip.mode:
application_server` lands.

**2b. Functional alias (24.379 clause 9A).** *Fix the event-package collision first* — today an FA
activation PUBLISH gets a `200 OK` and is silently discarded, and any unrecognised SUBSCRIBE
`Event` defaults to `"affiliation"`. Add an event whitelist before adding features, because the
current behaviour silently corrupts client state.

**2c. Ad hoc group call (24.379 clause 17)** — setup, release, rejoin, modify participants and
criteria, participant determination.

**2d. Multi-talker floor control (24.380)** — a real TLV parser (the current code never walks the
field list), the timer set, the server state machine, the four post-Rel-13 subtypes, and field IDs
014-025. Replace the scalar `FloorHolder` with a talker set carrying per-talker T1/T2/T20.

*Exit:* FA activate/deactivate/take-over round-trips; an ad hoc call establishes with dynamically
determined membership; two talkers hold the floor concurrently with correct Floor Taken and Floor
Release Multi Talker; Floor Indicator bits reflect actual call type.

### Phase 3 — Configuration and group management conformance

Stop shadowing PUT (the generated-AUID regeneration that silently discards writes); XCAP node
selectors; `If-Match`/412 and `If-None-Match`/304; `xcap-error+xml`; 404 for missing documents;
`xcap-caps`; runtime XSD validation; change-triggered NOTIFY. Add `<FunctionalAliasList>` to the
user profile and the `org.3gpp.mcs.location-user-config` AUID. Fix the `byGroup` /`byGroupID`
directory-name bug and the missing `<supported-services>` element.

*Exit:* an administrator can provision a group and a user profile through standard XCAP writes and
read back what they wrote.

### Phase 4 — Introduce the profile seam and the flag as a no-op

Add the `frmcs` config section and its validation, the `profile` package, `profile.MCX` as default,
and wire the six hook points — all still resolving to base behaviour. `profile.FRMCS` exists but
overrides nothing yet.

*Exit:* `frmcs.enabled: true` with no FRMCS features implemented behaves **identically** to
`false`, proven by test. This is the checkpoint that the seam is in the right places.

### Phase 5 — FRMCS behaviour behind the flag

In order: FA label structure, wildcard expansion and organisation code; `restrict_to_adhoc`
enforcement; FA-addressed private call promotion to ad hoc group; the participant determination
engine plus the geographic and railway-topology data model (the largest single item here); railway
priority mapping and `Resource-Priority: Normal`; railway floor priority policy; REC alert/voice
coupling.

*Exit:* an INVITE carrying FIS-7970 criteria resolves to the correct participant set including
polygon matching; eligibility re-evaluates during the call; an REC-alert followed by REC-voice
behaves per FRS clause 10.11.

### Phase 6 — MCData

SDS first, then IPcon (GRE-over-UDP, H2H then H2N). Both are base MCX services; FRMCS mandates
them but does not change them much. Expect this to be a large phase — the audit scoped MCData at
2-3x MCVideo, needing SIP MESSAGE dispatch, a binary TLV codec, and an HTTP content server.

*Exit:* one-to-one and group SDS; an IPcon tunnel carrying application IP traffic.

### Client and conformance test strategy

With MCOP dropped, the server needs something to be validated against. Two useful facts from the
FRMCS architecture shape this.

**A controller-side app is the cheapest legitimate client, and needs no on-board equipment.**
Per TS 103 764 clause 4.2.4, train-side applications reach the FRMCS System through the **OBAPP**
reference point exposed by the On-Board FRMCS, and *all* of them — tight-coupled and loose-coupled
alike — first perform a Local Binding to authenticate with it. The difference is only what happens
next: tight-coupled applications then use the standard 3GPP MCX reference points, loose-coupled
ones use OBAPP API features and let the On-Board FRMCS host the MC client on their behalf. Either
way, a train-side app implies a TOBA in the path.

The controller side does not. **TSCTRL** is exposed specifically "for the use of controller devices
and applications", and TS 103 765-4 clause 7.2 states that VAS Controller Equipment (a dispatcher
system) reaches the FRMCS Service Domain over an ordinary MC client interface set: **CSC-1, CSC-2,
CSC-4, CSC-8** (identity, group management, configuration, key management), **MCPTT-1** and
**MCPTT-4** (control plane and floor control), **MCPTT-7** (media plane), plus **MCData-7** and
**MCData-SDS-1**. Note that TS 103 765-4 clause 7.1 says "VAS Controller functions are not
specified in the present document" — the interfaces are pinned, the application behaviour is not,
which is exactly the freedom you want when writing your own.

So: **build (or buy) a dispatcher/controller client first.** It is a first-class FRMCS entity
rather than a lab shortcut, it exercises the interface set this plan actually builds, and it needs
no On-Board FRMCS. It also happens to be the client that most needs the railway features in Phase 5
— dispatcher pre-emptive floor priority and REC initiation by addressed area are both controller
behaviours.

**Off-the-shelf caveat.** COTS MCX clients targeting Rel-17/18 MCPTT exist and are a reasonable
way to validate Phases 2-3. COTS *FRMCS* clients are a different matter — the ETSI FRMCS
specifications are first editions dated January 2026, so treat any vendor FRMCS claim as needing
verification against TS 103 765-2 clause 5.1.1 rather than taken at face value. Validating Phase 5
may well mean your own client either way.

**Test strategy.** Since "does the demo still work" is no longer the bar, each phase's exit
criteria should be backed by protocol-level tests rather than an interoperability anecdote: SIP and
RTCP-APP message-level fixtures asserting encodings and state transitions, XCAP request/response
pairs checked against RFC 4825 and 24.481/24.484 semantics, and — for Phase 4 specifically — a
regression asserting that `frmcs.enabled: true` and `false` produce identical behaviour until
Phase 5 lands. The existing test suite is thin and asserts mostly with substring matching, so this
is largely new work; budget for it inside each phase rather than as a separate one.

## 7. Where the P25 / ISSI work attaches

Not part of this plan, but the plan is shaped so it does not obstruct it. Phase 2a
(interconnection roles) is the shared prerequisite — a peer MC system, an IWF, and a GSM-R
gateway all connect the same way. The P25 gateway would attach at the `profile` seam and at
IWF-1, reusing the Phase 2d floor implementation, since TS 29.380 adds no new floor messages or
fields. Nothing in Phases 0-4 needs to be undone to add it.

## 8. Decisions worth your explicit confirmation

1. **Rel-19 as the target**, accepting that FRMCS-profiled behaviour follows the Rel-18 reading
   where the two differ.
2. ~~Whether MCOP SDK 3.0 compatibility is a constraint.~~ **Resolved 2026-08-12: it is not.**
   A purpose-built or off-the-shelf client is planned instead. Reflected in §2, Phase 2.0, and the
   client strategy in §6.
3. **Whether an IMS/SIP core is available** (or can be stood up) in the lab. It sets when
   `sip.mode: standalone` can be deleted.
4. **Whether MCData is in scope at all**, or whether the target is FRMCS voice only. It is
   FRMCS-mandatory, so "voice only" means "deliberately partial FRMCS" — a legitimate choice, worth
   making explicitly.

## 9. Risks

**The FRMCS specs are moving.** TS 103 764, 103 765-x and 103 792 are all first editions dated
January 2026. The FRMCS floor priority scheme is an editor's note; call queueing depends on an
in-flight 3GPP change request; MCData File Distribution, arbitration and network-initiated
deregistration are explicitly unspecified; IWF-3 is required by one document and declared unused
by another. Build Phase 5 to absorb change, and keep the railway policy in config rather than code
wherever the spec has not settled.

**V2 versus V3.** Several capabilities in the UIC documents are marked M-V3 or I-Vx and are not in
the validated V2 baseline. Decide which baseline you are targeting before Phase 5.

**Participant determination is a bigger item than it looks.** It needs a geospatial model, railway
topology, and continuous re-evaluation during a live call. It is the one Phase 5 item that is a
subsystem rather than a feature.

**Scope discipline on the flag.** The failure mode is FRMCS logic leaking into the base. The Phase
4 exit criterion exists specifically to catch that early, and it is worth re-running as a
regression test at the end of every subsequent phase.
