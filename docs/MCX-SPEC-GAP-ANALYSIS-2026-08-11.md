# VectorCore MCX — 3GPP MCX Spec Conformance Gap Analysis

**Date:** 2026-08-11
**Question answered:** what does `mcxas` implement, and what is missing, relative to the
3GPP MCPTT (MCX) specifications shipped in this repository.
**Baseline specs (all read directly from the PDFs under
`project-VectorCore-MCX/specs/Rel 13/`):**

| Spec | Title | Version read |
| --- | --- | --- |
| TS 24.379 | MCPTT call control; Protocol specification | V13.19.0 |
| TS 24.380 | MCPTT media plane control (floor control); Protocol specification | V13.14.0 |
| TS 24.481 | MCS group management (GMS); Protocol specification | V13.7.0 |
| TS 24.484 | MCS configuration management (CMS/CMC); Protocol specification | V13.11.0 |
| TS 33.179 | Security of MCPTT over LTE | V13.12.0 |
| TS 24.383 / 24.384 | MCPTT MO / config management | V13.4.0 (24.384 body is void in Rel-13; content moved to 24.484) |

Every clause number below was confirmed against the PDF text by the reviewers. Where a
clause could not be confirmed, it is marked as such. The implementation is **on-network
only**; off-network (ProSe) procedures are noted where relevant but are out of scope for
what the code targets. The Go toolchain is not installed on this machine, so nothing was
compiled — findings are by source inspection.

Companion document: [AUDIT-2026-08-11.md](AUDIT-2026-08-11.md) covers general code
quality, security posture, and P25 ISSI readiness. This document is strictly the 3GPP
conformance view.

---

## 1. Executive summary

`mcxas` implements a **thin, single-vertical slice** of MCPTT: enough SIP call control,
XCAP document generation, RTP relay, and RTCP-APP floor messaging to bring up a basic
prearranged group call with one vendor's client (the MCOP demo client). Measured against
the specs, it is an early prototype: **most of the MCX service surface is missing, and the
parts that exist are frequently non-conformant in ways a second interoperating
implementation would reject.**

Rough conformance by spec:

| Spec area | Implemented | Assessment |
| --- | --- | --- |
| TS 24.379 call control | Registration plumbing, one group-call path, affiliation-from-membership, xcap-diff SUBSCRIBE/NOTIFY | ~1 of ~20 procedure areas usable; private call, emergency, imminent peril, chat, broadcast, pre-established, MESSAGE-based services all missing |
| TS 24.380 floor control | 4 of 10 messages built, correct RTCP-APP framing, single-holder RTP gating | No state machine, no timers, no queue, Floor Taken never sent, mandatory fields omitted |
| TS 24.481 group mgmt | Group document generation, one AUID | PUT not honored, no node selectors, no regroup, no conditional requests |
| TS 24.484 config mgmt | All 4 config docs generated, correct MIME + ETags | PUT not honored, no validation/409, no node selectors |
| TS 33.179 security | none (IdMS shim only) | Actively non-conformant token profile; no TLS, KMS, MIKEY-SAKKE, SRTP, or any key type |

The single most consequential structural fact: the code is built as **one merged AS that
answers INVITEs itself and fans out its own INVITEs to members**, whereas TS 24.379
defines distinct *participating* (6.3.2) and *controlling* (6.3.3) MCPTT functions with a
B2BUA forwarding model. Most call-control non-conformances flow from that divergence.

---

## 2. TS 24.379 — Call control (on-network)

Structural note: sip.go is a single merged AS acting as UAS for all inbound requests,
answering INVITEs with its own SDP then fanning out "RX INVITEs" to registered members
(sip.go:547–689, 841–1181). It parses only a minimal subset of
`application/vnd.3gpp.mcptt-info+xml` (mcptt-request-uri / calling-user-id / session-type
/ calling-group-id; sip.go:992–1002, 2073–2094).

| # | Procedure | Clause(s) | Status | Missing |
| --- | --- | --- | --- | --- |
| 1 | 3rd-party REGISTER + service authorisation | 7.3.1, 7.3.2 | PARTIAL | Never parses the `message/sip` body, `<mcptt-access-token>`, or `<mcptt-client-id>`; no service authorisation; no MCPTT-ID↔IMPU binding (equates them). sip.go:393–467 |
| 2 | Service settings via PUBLISH (poc-settings) | 7.3.3–7.3.5, 7.3.1A | PARTIAL | Stores raw body, returns 200+ETag; no token processing, no Expires=0 log-off, Answer-Mode never extracted (AS hardcodes `Answer-Mode: Auto`, sip.go:1057). sip.go:305–329 |
| 3 | Affiliation | 9.1, 9.2.2.2, 9.3.1 | PARTIAL | Only the first `<affiliation>` element handled; no N2 limit / "102" warning, no expiry, no implicit affiliation, no simple-filter. NOTIFY reports "membership implies affiliation" — a non-conformant fake. sip.go:331–391, 2121–2134 |
| 4 | Prearranged group call | 10.1.1, 6.3.3, 6.3.5, 6.3.6 | PARTIAL | Admits on **membership, not affiliation**; sends 200 OK before any member is invited (no TNG1/TNG3, no acknowledged setup); no MCPTT session identity / `isfocus`; no group-doc retrieval; forces `Answer-Mode: Auto`; no re-join/late-entry/re-INVITE upgrade. sip.go:547–689, 942–1181 |
| 5 | Chat group call | 10.1.2 | MISSING | `<session-type>` never read; all INVITEs take the prearranged mass-invite path |
| 6 | Broadcast group call | 4.12, 10.1.1.4.2 | MISSING | `<broadcast-ind>` never parsed |
| 7 | Emergency group call + alert | 4.6.1, 6.3.3.1, 12.1 | MISSING | No `emergency-ind`/`alert-ind`, no `Resource-Priority` (RFC 4412/8101), no emergency state. Emergency alert uses SIP MESSAGE, which is unhandled |
| 8 | Imminent peril | 4.6.4, 10.1.1.4.8 | MISSING | No `imminentperil-ind` |
| 9 | Private call (auto + manual commencement) | 11.1.1, 6.3.2.2.5/.6 | MISSING | Private INVITE is answered by the AS itself; **the called user is never invited** (fan-out only runs for group URIs). resource-lists never used for target selection. sip.go:686–688, 1791–1793 |
| 10 | Emergency private call | 4.6.2, 11.1.1.4.3 | MISSING | Follows from #7/#9 |
| 11 | Pre-established session | Clause 8 | MISSING | SIP REFER unhandled (405); no pre-established concept |
| 12 | Floor-control signalling in call control | 6.4, Annex J.1 | PARTIAL | Answers the floor m-line but unconditionally grants `mc_granted;mc_implicit_request` (violates 6.4 conditionality); RX INVITEs omit the floor m-line; INFO floor-request package not processed. sip.go:1702–1760 |
| 13 | MBMS bearer announcement | 14.2 | MISSING | SIP MESSAGE + mbms-usage-info unhandled |
| 14 | Location reporting | 13.2 | MISSING | mcptt-location-info + MESSAGE unhandled |
| 15 | Conference event package | 10.1.3 | MISSING | Only xcap-diff/pidf NOTIFY bodies; a conference SUBSCRIBE gets a bogus pidf |
| 16 | MCPTT Warning texts | 4.4.2 | MISSING | No `Warning:` header ever emitted (119/120/121/101/102/140) |
| 17 | MCPTT session identity | 4.5 | MISSING | 200 OK Contact is the plain AS URI, no `isfocus` |
| 18 | Mandated methods/headers | 6.3.1, 8, 12–14 | MISSING | MESSAGE/REFER/PRACK → 405 despite being advertised in `Allow` (sip.go:2233); incoming feature tags / ICSI never validated; P-Asserted-Service / Accept-Contact never generated |

**Not applicable to Rel-13:** first-to-answer, ambient listening, remote-change — no
clauses exist in Rel-13 TS 24.379 (introduced in later releases).

**Highest-impact call-control gaps, ranked:**
1. **No SIP MESSAGE support** — single-handedly blocks emergency alert, location, and
   MBMS (three whole service areas).
2. **Private calls never reach the callee.**
3. **No emergency / imminent-peril / Resource-Priority** anywhere.
4. **200 OK sent before members are invited + forced Answer-Mode Auto** — breaks
   commencement-mode semantics for every call type.
5. **Affiliation is faked from membership** rather than tracked per 9.2.2.2.

---

## 3. TS 24.380 — Media plane / floor control

The message set, field IDs, and RTCP-APP framing are confirmed against the PDF (Table
8.2.2.1-1, Table 8.2.3.1-2). The code's subtype numbering (observer.go:341–357) and length
word (596–609) match the spec exactly — that part is correct.

**Messages — built vs parsed:**

| Message | Clause | Built? | Gap |
| --- | --- | --- | --- |
| Floor Request | 8.2.4 | parse header only | No TLV fields parsed → Floor Priority ignored → no arbitration |
| Floor Granted | 8.2.5 | BUILT (589–610) | **Missing Floor Priority + Granted-Party SSRC (field 14); header SSRC is the requester's, not the server's** (600) |
| Floor Taken | 8.2.9 | **NEVER BUILT** | Group members are never told the floor was taken — a core controlling-function duty (6.3.4.4.2) |
| Floor Deny | 8.2.6 | BUILT (612–620) | **No Reject Cause field** — bare 12-byte header; header SSRC wrong |
| Floor Release | 8.2.7 | parse only | — |
| Floor Idle | 8.2.8 | BUILT (622–630) | **No Message Sequence Number**; sent only to releasing sender, never to the group (137); no T7 repetition |
| Floor Revoke | 8.2.10 | never sent | Advertised grant Duration never enforced by revocation |
| Floor Queue Position Info | 8.2.12 | BUILT (632–640) | **No Queue Info field (position+priority)** — pure stub, and no queue behind it |
| Floor Queue Position Request | 8.2.11 | parse (153–170) | Never actually queues |
| Floor Ack | 8.2.13 | MISSING | Ack-bit not handled: subtype mask 0x1f (584) maps ack-set messages to unknown subtypes |

**State machines / timers / queue:**

| Requirement | Clause | Status |
| --- | --- | --- |
| Controlling-function general state machine (G: Idle / Taken / pending Revoke / Releasing) | 6.3.4 | MISSING — only a per-call state *string* in the DB, no transitions enforced |
| Per-participant server state machine | 6.3.5 | MISSING — one `FloorHolder` string per call |
| Dual-floor / override | 6.3.6, 4.1.1.4 | MISSING |
| Participating-function relay | 6.4, 9.3 | MISSING |
| **All server timers** T1/T2/T3/T4/T7/T8/T9/T20 + counters C7/C20 | Clause 11 | MISSING — **zero timers of any kind**; `FloorGrantDuration` is advertised but never enforced (no revoke on expiry, no end-of-media detection) |
| Floor request queue (priority-ordered, grant-from-head on release) | 6.3.4, 14.2.2 | MISSING — grant-or-deny only |
| Priority arbitration / pre-emption | 4.1.1.4 | MISSING — first-holder-wins |
| Granted party identity = MCPTT ID | 8.2.3.6 | MISSING — holder is `ssrc:%08x` |
| Per-session SDP-negotiated floor channel | 4.3, 12, 14 | PARTIAL — one global floor port for all calls, matched by source IP |
| SRTP/SRTCP media-plane security | Clause 13 | MISSING — plaintext |
| Pre-established (MCPC Connect/Disconnect) | 8.3, 9 | MISSING |
| MBMS subchannel control (MCMC Map/Unmap) | 8.4, 10 | MISSING |

**Note:** TS 24.380 mandates **no codec** (AMR-WB lives in TS 26.179) — the code being
codec-agnostic is not a 24.380 gap. "Floor Release Multi-talker" does **not** exist in
Rel-13 and was not counted.

---

## 4. TS 24.481 — Group management (GMS)

The XCAP server is a flat path-keyed store; five AUIDs are always regenerated from DB
state on GET, so **PUT of a generated document is silently shadowed and never served
back** — the dominant defect on this interface.

| Requirement | Clause | Status | Gap |
| --- | --- | --- | --- |
| Group doc create / update (PUT) | 6.3.2.3, 6.3.4.3 | PARTIAL→MISSING | Stored but never served (regenerated from `groups` table); no schema validation; no If-Match/412 |
| Group doc retrieval (GET) | 6.3.3.3 | PARTIAL | Works, but never returns **404** — fabricates a group doc for any URI |
| Group doc delete (DELETE) | 6.3.5.3 | PARTIAL | Missing doc returns 204 not 404; generated docs undeletable; no tree pairing |
| Node selectors — element/attribute/namespace ops | 6.3.6–6.3.12 | MISSING | No `~~` parsing at all; node-selector URIs treated as whole-document paths (corrupts the tree model) |
| Group doc subscription/notification (CSC-5) | 6.3.13 | PARTIAL | Initial NOTIFY only (in sip.go); **no change-triggered NOTIFY** — a PUT/DELETE never notifies subscribers |
| Temporary group / regroup (GMOP, HTTP POST) | 6.3.14–6.3.16 | MISSING | POST → 405; no GMOP handling |
| Inter-provider group routing, asserted identity, TLS | 6.2.5 | MISSING | No auth, plain HTTP |
| `byGroupID` global-tree addressing | 7.2.10.2 | BUG | Code matches `/global/byGroup/` — wrong dir name (`byGroup` vs `byGroupID`), so conformant clients fall through. server.go:698–709 |
| Users-tree ↔ byGroupID pairing/propagation | 7.2.11.2 | MISSING |
| Group doc qualifies as MCPTT group (`<supported-services>`) | 7.2.8 | PARTIAL | Generated doc **lacks `<supported-services>`**, so by 7.2.8 it is not an MCPTT group document. Also uses unconfirmed element names (`max-participant-count`, `allow-initiate-conference`) |
| GKTP group-key-transport doc (`org.3gpp.MCPTT-GKTP`) | 7.7 | MISSING |

---

## 5. TS 24.484 — Configuration management (CMS/CMC)

All four config documents are generated with **correct MIME types and strong ETags**
(matching Annex B.1.1–B.1.4) — the best-conforming corner of the codebase. But the same
generate-only / PUT-shadowed model applies.

| Requirement | Clause | Status | Gap |
| --- | --- | --- | --- |
| Document create/update (PUT of ue-init-config, ue-config, user-profile, service-config) | 6.3.2.3, 6.3.4.3 | MISSING in effect | All four are generate-only; admin-PUT stored but never served; no If-Match/412 |
| Document retrieval (GET) | 6.3.3.3 | PARTIAL | Correct MIME + ETag; but unknown AUID returns fabricated 200 not 404 |
| Document deletion (DELETE) | 6.3.5.3 | PARTIAL | Missing doc → 204 not 404; generated docs undeletable |
| Node selectors (element/attribute/namespace) | 6.3.6–6.3.12 | MISSING | 5.2 makes these **shall** for the CMS |
| Subscription/notification (CSC-5) | 6.3.13 | PARTIAL | Initial NOTIFY only; ue-init-config not in default selector set; no MIKEY/CSK |
| Validation constraints → **HTTP 409 `<constraint-failure>`** (wrong AUID/XUI/semantic) | 7.x.2.6 | MISSING | Zero validation; any bytes/Content-Type/path stored |
| service-config global + read-only to users | 7.5.2.9 | PARTIAL | Path works; no read-only enforcement |

---

## 6. Cross-cutting XCAP (RFC 4825, normative for both 24.481 and 24.484)

| Item | Status | Note |
| --- | --- | --- |
| Node selectors (`~~`, el/attr/namespace) | MISSING | Document- and node-selector conflated into one flat path string |
| Conditional requests (If-Match/If-None-Match, **412**, 304) | MISSING | Headers never read. A test (server_test.go:566–601) **asserts the non-conformant behavior** (200 + full body on matching If-None-Match) |
| `application/xcap-error+xml` bodies | MISSING | All errors are text/plain `http.Error` |
| 404 for missing resource | NON-CONFORMANT by design | GET never 404s; DELETE returns 204 for missing |
| `xcap-caps` AUID (RFC 4825 §12, mandatory) | MISSING |
| PUT body size limit / MIME enforcement | MISSING | Unbounded `io.ReadAll`; Content-Type echoed verbatim |
| Runtime XSD validation | MISSING | Validation exists only in a test that `t.Skip`s when `xmllint` is absent |

---

## 7. TS 33.179 — Security

Split into **actively non-conformant** (the code does something the spec forbids) and
**simply unimplemented**.

### Actively non-conformant
1. **`alg:none` unsigned JWTs** (idms.go:135) vs Annex B.1.2's mandatory RFC 7515 JWS
   signature. The token *format itself* violates the profile; any conformant resource
   server rejects every token this IdMS issues. Same token reused as access_token and
   id_token.
2. **Authorization endpoint issues a static code (`vectorcore-dev-code`) with no user
   authentication** (idms.go:22–46); token endpoint ignores grant_type/code/client_id;
   identity inferred by source IP or "first enabled user" fallback (idms.go:99–133). This
   inverts clause 5.5's defining step (the user proving identity).
3. **`exp`/`iat` emitted as JSON strings**, violating B.1.1.1's JSON-number requirement.
4. **Missing REQUIRED claims:** no `aud` (id token), no `scope` (access token) — the
   `3gpp:mc:ptt_service` etc. scopes are never issued.
5. **UE config advertises `integrity-protection-enabled=false` and
   `mutual-authentication=false`** (cms/server.go:333–341) — affirmatively tells clients
   to disable protection.

### Unimplemented (mandatory capability absent)

| Mechanism | Clause | Status |
| --- | --- | --- |
| TLS/HTTPS on IdMS (CSC-1) | 5.5.1, B.7 | MISSING — plain HTTP |
| TLS on HTTP-1 / XCAP | 6.2, 5.4 | MISSING — plain HTTP :8100 |
| SIP-1 protection / IMS AKA | 5.3, 6.1 | MISSING (partly SIP-core's responsibility) |
| KMS + identity keying (CSC-8/9/10) | 7.2 | MISSING — `kms_uri` is just an echoed string |
| GMK / GUK-ID via MIKEY-SAKKE | 7.3 | MISSING |
| PCK (private call) | 7.4 | MISSING |
| SRTP media protection | 7.5 | MISSING — plaintext RTP |
| SRTCP floor/media control protection | 7.6, 9.4 | MISSING — plaintext floor |
| MKFC / MSCCK (multicast/MBMS keys) | 7.3.2, 7.7 | MISSING |
| CSK (client↔server signalling key) | 9.1 | MISSING — access token in SIP PUBLISH never validated |
| SPK (server↔server) + NDS/IP | 9.2, 8.1 | MISSING |
| XML protection (xmlenc AES-128-GCM, xmlsig HMAC-SHA256) | 9.3 | MISSING |
| Key-derivation machinery (RFC 3830 PRF → SRTP master keys) | 7.3.6, 7.4.4, 9.4.5 | MISSING — no crypto primitives at all |

Every key type mandated by the spec — GMK, GMK-ID, GUK-ID, User Salt, PCK, PCK-ID, CSK,
SPK, MKFC, MSCCK, KFC, TGK, XPK, TrK, KMS-issued SAKKE/UID keys — has **zero
representation** in the code.

---

## 8. What is actually conformant (worth preserving)

- **TS 24.484 config-document generation**: correct AUIDs, MIME types, and strong ETags
  matching Annex B; the generated user-profile passes the Rel-13 XSD in tests.
- **RTCP-APP floor framing**: message subtype numbering, field IDs 1/13, Floor Indicator
  bit A (Normal call = 0x8000), and the length word all match TS 24.380 tables.
- **SIP plumbing**: third-party REGISTER 200-without-Contact rule, basic RFC 3261 mechanics
  (CANCEL→200+487, 481 for unmatched in-dialog, Via/tag handling, NOTIFY CSeq monotonicity),
  and xcap-diff SUBSCRIBE with an initial NOTIFY carrying per-document ETags.
- **RTP floor gating**: rejecting RTP from a non-holder SSRC is the correct media-distributor
  behavior in spirit (though it fails open when no holder is set).

---

## 9. Bottom line

Against the shipped MCX specs, `mcxas` is a **demonstrator, not an MCX implementation**.
It brings up one prearranged group call with one cooperating client and generates the
config/group XML those clients fetch, but:

- **Call control** covers roughly one of the ~20 procedures TS 24.379 defines; the
  service-defining features (private, emergency, imminent peril, chat, broadcast,
  pre-established, alert, location, MBMS) are absent, most of them blocked by the single
  fact that SIP MESSAGE and REFER are unhandled.
- **Floor control** has no controlling-function state machine, no timers, no queue, and
  never tells the group the floor was taken — it cannot arbitrate a real multi-party PTT
  session.
- **Group/config management** generates documents correctly but cannot be provisioned via
  the standard XCAP write/patch model, and returns non-conformant status codes.
- **Security** is not merely unimplemented — the IdMS actively issues tokens the profile
  forbids, and no TLS, KMS, MIKEY-SAKKE, SRTP, or key material exists anywhere.

For interoperability with any second (non-MCOP-demo) MCX implementation, the conformance
gap is large and spans every interface. The realistic path is to treat the current code as
a reference harness for the happy path and rebuild call control around the
participating/controlling function split, add a real floor-control state machine, adopt
the standard XCAP write model, and layer in the 33.179 security plane — in that order.
