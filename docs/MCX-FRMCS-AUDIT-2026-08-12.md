# VectorCore MCX — MCX Conformance and FRMCS Readiness Audit

**Date:** 2026-08-12
**Subject:** `mcxas` (Go MCX/MCPTT IMS Application Server), `B:\vectorcore-mcx` @ `9c5af04`
**Questions answered:**
**A)** What is missing on the MCX side relative to the 3GPP Mission Critical specifications.
**B)** What would be required to add FRMCS (Future Railway Mobile Communication System) support.

Supersedes the Rel-13-only analysis in
[MCX-SPEC-GAP-ANALYSIS-2026-08-11.md](MCX-SPEC-GAP-ANALYSIS-2026-08-11.md).
General code quality, security posture and P25 groundwork are in
[AUDIT-2026-08-11.md](AUDIT-2026-08-11.md).

---

## 0. Method and evidence base

**Spec library:** `Y:\Standards and Specs` — 3,447 files. Two collections were used:

| Collection | Content |
| --- | --- |
| `MCX_LTE_NR_GSM_GSMR\mcx\` | 3GPP **Release 19** MC set: TS 22.179/22.280/22.281/22.282/22.289, 23.280/23.281/23.282/23.283/23.289/23.379, 24.281/24.282/24.283/24.379/24.380/24.481/24.482/24.483/24.484/24.581/24.582, 29.379/29.380/29.582, 33.180 |
| `MCX_LTE_NR_GSM_GSMR\Rel-20\` | Early **Release 20** drafts (v20.x) of the same series |
| `FRMCS Specs\uic\` | UIC **FU-7100** URS v5.0.0, **FU-7120** FRS v2.1.0, **AT-7800** SRS v2.1.0, **FFFIS-7950** v2.1.0, **FIS-7970** v2.1.0, **TOBA-7510**, **TOBA-7540**, **MG-7900** |
| `FRMCS Specs\` (ETSI) | **TS 103 764** System Architecture, **TS 103 765-1..5** Building Blocks, **TS 103 792** GSM-R Interworking — all V1.1.1, 2026-01 |

**Extraction.** 3GPP `.docx` were converted by parsing `word/document.xml` directly; the four
legacy `.doc` files (22.179, 22.280, 22.989, **29.380**) were recovered by parsing the OLE2
Word piece table. PDFs via `pdftotext -layout`. All clause numbers below were read out of the
resulting text by the reviewers, not recalled from memory; items that could not be confirmed
are marked as such rather than asserted.

**Release baseline verified, not assumed.** Clause-heading sets were diffed between releases:

- TS 23.283 — Rel-19 (v19.5.0) and Rel-20 (v20.1.0): **273 headings each, identical.**
- TS 24.379 — Rel-19: 794 headings; Rel-20 (v20.0.0): 793. TS 24.380 — 396 in both.

Rel-20 adds no new clauses to MCPTT call control, floor control, or LMR interworking. **Rel-19
is therefore the correct and sufficient audit baseline**, and nothing here will be invalidated
by the Rel-20 drafts already in the library.

**Limits of this audit.** The Go toolchain is not installed on this machine, so nothing was
compiled and no test was run — findings are by source inspection. The UIC PDFs are two-column
documents whose extracted text places clause IDs in a left gutter offset by several lines from
the sentence they label; **section-level IDs (`10.11`, `8.2.8`, `21.2.4.1`) are reliable, but
sub-clause-to-sentence bindings from the UIC documents must be re-verified against the PDF
before being quoted as requirement numbers.** TS 22.280 and TS 22.179 stage-1 text was not
available in extractable form, so the stage-1 origin of functional alias / multi-talker /
MC gateway UE could not be confirmed. FRS Appendix G (common-function matrix) and Appendix I
(arbitration tables) were located by reference but not read.

---

# PART A — What is missing on the MCX side

## A.1 Headline

`mcxas` implements a narrow slice of **one** of the three MC services, against a spec release
that is six generations old, with no security plane and no interconnection model. Measured
against the Rel-19 MC specification set it is a **single-vendor demonstrator**.

The two structural facts that dominate everything below:

1. **Of the roughly 30 application-plane reference points defined in TS 23.280 clause 7.5.2,
   the code touches two — CSC-2 and CSC-4 — and only their HTTP GET half.** Every other
   interface, including all six that carry security material, does not exist.
2. **The code is a standalone fused SIP endpoint.** It terminates REGISTER itself, which is
   the SIP core's role. The MC architecture expects an Application Server sitting behind an
   IMS/SIP core on the ISC reference point (SIP-2). This single choice forecloses third-party
   registration, UE capability signalling, and both the LTE (Rx) and 5GS (N5) resource-management
   paths, because none of them have an attachment point.

## A.2 The release-baseline problem

The README targets "3GPP Release 13 MCPTT interoperability". That is a defensible choice for a
lab demonstrator, but it has a hard consequence that matters for Part B:

> **FRMCS normatively requires Release 18 or later** (ETSI TS 103 765-2 clause 4.1, with every
> 3GPP reference pinned to a specific Rel-18 version). A Rel-13 baseline is not a subset of what
> FRMCS needs — several FRMCS-mandatory features (ad hoc group calls, functional alias,
> multi-talker) **do not exist at all in Rel-13**.

So the release gap is not cosmetic tidying. It is the gap.

## A.3 Reference points and functional entities (TS 23.280)

| Entity | Clause | Status |
| --- | --- | --- |
| Configuration management server (CMS) | 7.4.2.2.2 | **Partial** — the only entity with real code |
| Group management server (GMS) | 7.4.2.2.4 | **Partial/conflated** — no separate entity; group docs emitted by the CMS process. Media policy and group call policy never generated |
| Identity management server (IdMS) | 7.4.2.2.6 | **Not implemented** — see A.7 |
| Key management server (KMS) | 7.4.2.2.8 | **Absent** — `kms_uri` is a string echoed into XML |
| Location management server (LMS) | 7.4.2.2.10 | **Absent** |
| Functional alias management server | 7.4.2.2.13 | **Absent** — and note the spec assigns this role to the CMS, i.e. it is a gap *inside* the one entity that exists |
| MC service server | 7.4.2.3.2 | **Partial** — does not perform the functional alias controlling role |
| MC service user database | 7.4.2.3.3 | **Partial** — no CSC-13 interface; CMS reads the store in-process |
| MC gateway server | 7.4.2.3.4 | **Absent** |
| SIP core, Diameter proxy, SIP database, HTTP proxy | 7.4.3.x | **Absent** — the AS fuses these roles |

**Reference points.** CSC-2 and CSC-4 partial (HTTP GET only). **Absent entirely:** CSC-1
(non-conformant, see A.7), CSC-3, CSC-5, CSC-7, CSC-8/9/10 (KMS), CSC-11/12, CSC-13, CSC-14/15
(location), CSC-16/17 (interconnection/migration), CSC-19/20/21/22/23/24, MCX-1, ACM-1/2/3, Le.
On the signalling plane, SIP-1/SIP-2/SIP-3, HTTP-1/HTTP-2/HTTP-3 and AAA-1/AAA-2 are not
distinguishable interfaces — there is one fused SIP endpoint and one fused HTTP endpoint.

**Common MC services with no concept in the code at all** — each confirmed in 23.280:
functional alias management (8.1.5, 10.13, 10.1.7), location management (10.9 in full),
migration (5.2.9, 10.6.3, 10.16), interconnection (5.2.10, 10.14, 10.17), MC gateway server,
service continuity (10.7.3.7), emergency alert (10.10.1), pre-established sessions (10.3),
MBMS (10.7), preconfigured regroup (10.15). Resource management and priority (10.11, 10.12)
exist only as static XML literals in the generated service-config — there is no Rx/N5
interaction and no arbitration.

*Not gaps:* recording/replay (7.4.2.4) and CSC-25 are explicitly out of scope of 23.280 v19.
ACM (7.4.2.5) and Le are in scope and absent. The participating/controlling/non-controlling
role split is a 23.379 construct, not 23.280 — it was not verified against 23.379 here.

## A.4 MCPTT call control (TS 24.379 v19.7.0)

The Rel-13 gap list from the prior audit still stands in full: no private call that reaches the
callee, no emergency or imminent peril, no Resource-Priority, no chat or broadcast group call,
no pre-established sessions, no MCPTT session identity / `isfocus`, no Warning header texts,
affiliation faked from static membership, and MESSAGE / REFER / PRACK returning 405 despite
being advertised in `Allow`.

**On top of that, the following Rel-14 to Rel-19 features are absent.** A repo-wide grep across
`internal/sip/sip.go` for the whole feature vocabulary returns exactly one hit — an
`Answer-Mode: Auto` header added as a client workaround.

| Feature | Clause | Note |
| --- | --- | --- |
| **Functional alias** | **4.14, 9A** | See A.4.1 — actively mishandled, not merely missing |
| First-to-answer call | 11.1.1 | Identified by Request-URI = PSI **and Contact without `isfocus`** |
| Ambient listening call | 11.1.6 | incl. 11.1.6.4.3 server-initiated release |
| Remotely initiated private call / group call | 11.1.7 / 10.1.5 | |
| Remote change of selected group | 10.1.4 | |
| Private call call-back | 11.1.5 | request/cancel/response, all over SIP MESSAGE |
| Private call transfer / forwarding | 11.1.8 / 11.1.9 | forwarding needs timer TNP1 (6.3.2.5) |
| **Ad hoc group call** | **clause 17** | incl. 17.3.6 participant determination — **FRMCS-critical** |
| **Ad hoc group emergency alert** | **12.1A** | **FRMCS-critical** |
| Emergency alert enhancements | 12.1.3.4, 12.1.1.4, 12.1.1.6 | geo-fenced alert areas, late alert to late joiners |
| Imminent-peril state cancel; third-party emergency cancel | 10.1.6; 6.2.8.1.14, 6.2.8.3.8 | |
| Priority via in-dialog INFO; RPH retrieval/correction | 6.2.8.1.13, 6.3.3.1.18; 6.3.3.1.19, 6.3.3.1.8 | code accepts INFO/UPDATE but gives them generic 200s |
| Priority sharing | 6.7 | needs Rx/N5 |
| Regroup using a preconfigured group | **clause 16** | group regroup 16.2 and **user** regroup 16.3 |
| Temporary group session, non-controlling initiated | 10.1.1.5.5 | |
| MCPTT gateway server / gateway UE | 5.5, 6.8 / 5.6 | |
| Migration to a partner MCPTT system | **7A** | |
| MBMS / **5G MBS** | 14 / **14B** | MBS is genuinely new: session announcement, MuSiK, join notification |
| **MCPTT over 5GS** | **Annex L** (normative) | PDN to PDU session, bearer to QoS flow, N5/N33/NEF, MBMS/MBS term mapping |
| Service continuity (UE-to-network relay) | 14A | |
| Location procedures | 13.2, 13.3 | incl. server-to-server location request |
| Conference event package | 10.1.3 | no `conference` event in the SUBSCRIBE handler |
| Implicit affiliation; rules-based; negotiated-mode | 9.2.2.2.12-.14; 9.2.1.7; 9.2.1.4/.5 | |
| Subscription to group dynamic data | 9.2.1.6 plus 24.380 8.5, 10A.1 | |
| XML confidentiality / integrity protection | 4.8, 6.6 | separate from transport security |

**Not confirmable — do not treat as requirements.** "Location-dependent group call/routing" has
**zero** occurrences in 24.379 or 23.379; the real features are geographic-area triggers
(12.1.1.4, 12.1.1.6) and location-based FA status change (9A.2.1.4). "Multi-talker" has zero
occurrences in 24.379 — it is a 24.380 media-plane feature configured via 24.481/24.484.
**IWF procedures are not in 24.379 at all** (see A.10).

### A.4.1 Functional alias — an active conformance collision

This is the most important single finding in Part A, because functional alias is the backbone of
FRMCS identity (Part B) and because the code does something **worse than not implementing it**.

Per clause 9A.2.1.2, FA status change is a **SIP PUBLISH** carrying
`application/vnd.3gpp.mcptt-info+xml` plus `application/pidf+xml`, with `Expires: 4294967295`
to activate or `Expires: 0` to deactivate. That is the *same transport the code has already
claimed for affiliation*:

- `handlePublish` (sip.go:305) routes `Event: presence` to `handlePresencePublish` (sip.go:331).
- That handler looks for an affiliation in the pidf body and, finding none, **returns `200 OK`
  with a SIP-ETag and silently discards the request** (sip.go:337-341).
- **Result: an FA activation is acknowledged as successful and thrown away.** The client believes
  its functional alias is active. The server has no FA state whatsoever.
- `Expires` is never read on the PUBLISH path, so the activate/deactivate distinction is invisible.

The same collision exists on SUBSCRIBE: sip.go:470-473 defaults an absent or unrecognised `Event`
header to `"affiliation"` with **no whitelist**, so an FA status-determination or FA resolution
subscription (9A.2.1.3, 9A.2.2.3.7/.3.8) — and equally a conference event package subscription
(10.1.3) — is silently answered with affiliation data from a different event package.

Also missing across the FA cluster: automatic deactivation (9A.2.2.3.6), server-to-server FA
procedures (9A.2.2.2.6/.2.7), the `take-over-possible` state (the code's state mapper knows only
affiliated/affiliating/deaffiliating/deaffiliated), FA-to-group binding (9A.4, over SIP MESSAGE,
which 405s), the pidf and simple-filter schema extensions (9A.3.1, 9A.3.2), FA Warning texts
171/172/176/177/178/201, and the media-plane FA fields (24.380 8.2.3.19, 8.2.3.20).

## A.5 Floor control (TS 24.380 v19.2.0)

The RTCP-APP framing, subtype numbering for the original messages, field IDs 1 and 13, and the
Floor Indicator "Normal call" bit are all correct. Everything below is on top of the already-noted
Rel-13 gaps (no state machine, no timers, no queue, Floor Taken never sent, mandatory fields
omitted from Deny and Idle).

**Four message subtypes added after Rel-13, none implemented.** The code's constants stop at
`mcpttFloorAck = 10`:

| Subtype | Message | Clause |
| --- | --- | --- |
| `00111` (7) | **Floor Revoke Request** | 8.2.17 |
| `x1011` (11) | **Unicast Media Flow Control** | 8.2.16 |
| `x1110` (14) | **Queued Floor Requests** | 8.2.15 |
| `01111` (15) | **Floor Release Multi Talker** | 8.2.14 |

**Twelve field IDs added after Rel-13 (014 to 025), none implemented** — and note the parser never
walks the TLV list at all, reading only the subtype bits and the SSRC, so *no* field of *any* ID is
ever decoded. The new IDs: Audio SSRC of Granted Participant (014), List of Granted Users (015),
List of SSRCs (016), **Functional Alias (017)**, **List of Functional Aliases (018)**, Location
(019), List of Locations (020), Queued Floor Requests Purpose (021), List of Queued Users (022),
Response State (023), Media Flow Control Indicator (024), Floor Revoke Request User ID (025).

**Multi-talker control (clause 4.1.1.2, server arbitration 6.3.4.4.7a)** is absent at every level,
and this is the one place where **Rel-13-correct code is now Rel-19-wrong**:

- The floor is modelled as a single scalar `FloorHolder` string; the spec requires a list of
  granted MCPTT IDs with **one instance of timers T1, T2 and T20 per granted talker**.
- `floorCanGrant` (observer.go:513) refuses a second grant while a holder exists — so in a
  multi-talker group it **denies valid floor requests**.
- `rtpAuthorizedForFloor` (observer.go:444) drops RTP from any non-holder SSRC — so it
  **discards legitimate concurrent media**.
- On release the server must emit **Floor Release Multi Talker** to the other participants; the
  code synthesises a Floor Idle instead.
- The Floor Indicator is hardcoded to `0x8000` (bit A, "Normal call"), so it can never signal bits
  D (emergency), E (imminent peril), F (queueing), G (dual floor), **H (temporary group)** or
  **I (multi-talker)** — and it affirmatively mis-states "Normal call" for every one of them.

Also new and absent: 5G MBS media-plane subchannel control (8.6, clause 10B) and the MBMS
notification / Group Dynamic Data Notify family (8.5, 10A.1).

## A.6 Group and configuration management (TS 24.481 v19.3.0 / TS 24.484 v19.6.0)

The Rel-13 findings carry over unchanged and remain the dominant defects: **PUT is accepted then
silently shadowed** because GET always regenerates the five generated AUIDs; no XCAP node
selectors; no `If-Match`/412 (with a test asserting the wrong behaviour); no `xcap-error+xml`; no
404 for missing documents; no `xcap-caps`; no runtime XSD validation; no change-triggered NOTIFY;
no GMOP/regroup (POST returns 405); the `byGroup` versus `byGroupID` directory-name bug; and a
generated group document lacking `<supported-services>`, which per 24.481 clause 7.2.8 means it
does not qualify as an MCPTT group document.

Rel-19 additions on top: the CMS must serve the **functional alias management server** role
(23.280 7.4.2.2.13) including a `<FunctionalAliasList>` in the user profile — without which a
client cannot even discover which aliases it may activate; and the AUID switch does not know
`org.3gpp.mcs.location-user-config`, so the configuration half of location services is unreachable
even before any location logic exists.

## A.7 Identity management (TS 24.482 v19.1.0)

TS 24.482 requires the IdM server to support the 33.180 authentication framework and, mandatorily,
**a username-and-password authentication method** (clause 5.2); to return HTTP 200 with a
credential form and authenticate the user before issuing a code (6.3.1); to derive the MC service
ID **from the authenticated credentials**; to support token exchange (6.3.2, RFC 8693) and
partner-domain tokens (6.3.3, RFC 7523); and to run everything over TLS.

The `/idms/*` shim is non-conformant on several counts that are **affirmatively forbidden** rather
than merely unimplemented:

| Requirement | Shim behaviour |
| --- | --- |
| Access token shall carry a JWS signature (33.180 B.2.2.1) | Emits `alg:none` with an empty signature |
| IdMS shall authenticate the user (24.482 5.2, 6.3.1) | No authentication at any point; straight to 302 |
| Authorization code bound to a user/session | Static constant `vectorcore-dev-code` for the system's lifetime |
| PKCE required; **request rejected if `code_challenge` absent** (33.180 B.4.2.2) | Never parsed; no `code_verifier` check. This is precisely the downgrade Rel-19 CR 0217 was raised to close |
| `redirect_uri` shall be pre-registered (B.3) | Taken verbatim from the query, giving an open redirect that leaks the code |
| TLS mandatory on CSC-1 (B.12) | Plain HTTP |

Plus: no `aud` claim (required in the ID token), no `scope` claim (required in the access token,
and the vehicle for the `3gpp:mc:*` service scopes), the same string returned as both
`access_token` and `id_token`, a constant refresh token, `grant_type` never branched on, and
identity resolved **by TCP source IP** with a fallback to *the first enabled user in the database*.
There is no configuration flag to disable the shim — it is registered unconditionally.

## A.8 Security (TS 33.180 v19.4.0)

Nothing from the security plane exists: no TLS on any interface, no KMS, no MIKEY-SAKKE, no
SRTP/SRTCP, no XML protection, and zero representation of any mandated key type.

Rel-19 additions beyond the Rel-13 picture, for scoping purposes: **KMS Redirect Responses and
multiple security domains** (5.2.8, 5.2.7, with Home/Migration/External KMS roles); **message
origin authentication via the Element for Authenticating Requests (EAR)** (9.6, including 9.6.5.2.2
for affiliation signalling and 9.6.2.5 for migrated users); **interconnection and migration
security** (clause 11, incl. 11.1.2.2 GMK transfer between MC systems); **MC gateway
authentication** (5.12); **regroup security** (7.3.3.2/.3, 7.3.11/.12); **multi-talker group
security** (7.3.10); new key types **MuSiK, MKFC, KFC, MSCCK, InK, DPPK/DPCK, InterSD/InterKMRec**;
the **MC Recording Server** with the `mcrec_id` claim and two new OIDC scopes; and 5GS access
security via TS 33.501. Functional aliases are named in 9.3.2 as content requiring confidentiality
protection.

*Caveat:* 33.179 was not in the extracted corpus, so the Rel-13 to Rel-19 framing above derives
from 33.180's own change history rather than a side-by-side diff.

## A.9 The two entirely missing MC services

MCX is three services. The code implements a partial version of one. This matters directly for
Part B, because FRMCS makes **MCData mandatory**.

### MCVideo (TS 24.281 / 24.581 / 23.281) — smaller lift than it looks

MCVideo's signalling control is structurally MCPTT-with-video: same group/private/emergency/
imminent-peril/affiliation/regroup/functional-alias/location architecture, same SIP methods, same
`-info+xml` body shape. Its media plane control is **the same RTCP-APP family** with an identical
packet header and identical TLV encoding rules, and **field IDs 000 to 014 occupy the same slots**
with equivalent semantics (Floor Priority becomes Transmission Priority, Granted Party's Identity
becomes User Id of the Transmitting User, and so on).

The differences that matter:

- **The APP name is split by direction:** `MCV0` (client to server), `MCV1` (server to client),
  `MCV2` (bidirectional), plus `MCV3`/`MCV4`/`MCV5` for MBMS/notification/MBS. **Subtypes collide
  across the three tables** — `x0000` is Transmission Request under MCV0 but Transmission Granted
  under MCV1 — so the parser must branch on the name string *before* interpreting the subtype. The
  current design, which switches on a bare subtype integer, breaks outright.
- **Reception control is a second, orthogonal state machine** (24.581 6.2.5, 6.3.6, 6.3.7, timers
  T5/T6/T11/T103/T104) governing who may *receive* which stream. There is no MCPTT analogue at all.
- **SDP is `m=application <port> udp MCVideo`** with `mc_transmission_ssrc` in the fmtp line, and
  that SSRC must be allocated per receiving entity and **rewritten at each hop** (24.281 6.3).
- New call types with no MCPTT equivalent: video pull (12.2), video push (13.2), remote video push,
  ambient viewing (15), capability information sharing (14).

### MCData (TS 24.282 / 24.582 / 23.282) — roughly 2 to 3 times the lift

Almost nothing carries over from MCPTT:

- **SDS and FD on the signalling plane ride SIP MESSAGE**, which the code 405s. Clause 6.3.1.1
  ("Distinction of requests at the MCData server") is a five-page dispatch table discriminating
  dozens of MESSAGE flavours — a bigger single piece of dispatch logic than anything currently in
  `sip.go`.
- **The media plane is MSRP (RFC 4975)**, not RTP, and the server must **terminate and re-originate
  MSRP legs** (24.582 6.2/6.3, 7.2/7.3), inspecting message bodies. RTCP-APP appears in 24.582 only
  for MBMS/MBS subchannel control.
- **A binary TLV codec is mandatory from day one**: 17 message types and 28 information elements
  carried in `application/vnd.3gpp.mcdata-signalling` and `-payload`. The code has no TLV parser.
- **Three new server roles that are not SIP entities at all**: the MCData content server / media
  storage function (HTTP upload and download), the MCData message store, and the MCData
  notification server. The message store speaks the **OMA NMS RESTful API**, whose resource
  definitions live in an OMA specification that is not in this library — so that piece cannot be
  scoped from 3GPP text alone.
- Communication release (clause 13) is a hidden tax: six initiator variants times two transports
  times three entities.

Confirmed capabilities: SDS (standalone signalling-plane, standalone media-plane, session,
pre-established), FD (over HTTP and over media plane), IP connectivity, enhanced status,
transmission and reception control, disposition notifications, deferred delivery, and the MCData
message store (clause 21, present in Rel-19).

**Flagged:** MCData **data streaming** is defined in 23.282 (5.5, 6.7) but has **no Rel-19 stage-3**
— 24.282 has no substantive coverage and 24.582 clause 4.1.3 is "Void". If data streaming is ever
a requirement, it cannot currently be implemented to spec.

**Sequencing note:** if both services are ever targets, do **MCVideo first**. It forces construction
of a generalised RTCP-APP plus TLV codec and a proper timer-driven state machine, both of which
retroactively upgrade the MCPTT floor implementation from stub to conformant, and the TLV codec is
directly reusable for MCData's 28 IEs. Doing MCData first buys nothing for MCVideo.

## A.10 LMR interworking — the finding that changes the P25/ISSI plan

**3GPP already specifies how to bridge MC services to Land Mobile Radio systems**, and this
library contains the whole set: **TS 23.283** (architecture), **TS 29.379** (IWF call control),
**TS 29.380** (IWF media plane control — recovered from legacy `.doc` for this audit), and
**TS 29.582** (IWF MCData). None of this was in the repo's own spec folder.

**The model.** An InterWorking Function sits outside the MC system and, together with its LMR
system, "will appear as a peer interconnected MC system" (23.283 clause 4). Four reference points:

| RP | Endpoints | Carries |
| --- | --- | --- |
| **IWF-1** | IWF to **MCPTT server** | A subset of **MCPTT-3** — call control, floor control, media |
| **IWF-2** | IWF to **MCData server** | SDS only |
| **IWF-3** | IWF to **group management server** | Group config, documents, regroup (based on CSC-16) |
| **IWF-4** | IWF to **location management server** | Optional |

Identity mapping is the IWF's job: LMR users and talkgroups appear to the MC system purely as
MCPTT IDs and MCPTT group IDs in the IWF's own SIP domain (23.283 clause 8.1). The IWF can play
the **controlling**, **participating**, or **non-controlling** role per call, selectable by which
system homes the group (29.379 clause 5.1).

**Three facts that bear directly on the ISSI plan:**

1. **P25 has no published LMR-side companion spec.** TS 23.283 is technology-agnostic; its only
   normative LMR references are TIA-603-D (analogue FM) and ETSI TS 100 392-19-1 (TETRA).
   **TIA-102 / ISSI is never referenced.** Annex A states plainly that study of P25/3GPP MC
   interworking "is under progress by ATIS and **not yet published**" — in a document dated
   January 2026. TETRA has a standard mapping; P25 does not.
2. **The LMR-facing half of the IWF is 100% out of 3GPP scope, on every path.** 23.283 clause 1
   ("the structure and functionality of the IWF is out of scope"), 29.379 clause 5.1 ("how the IWF
   serves LMR users is out of scope", stated twice), and most bluntly 29.380 clause 4.2.0 ("the
   floor control interface towards LMR entities is out of scope"). Roughly 30 further out-of-scope
   notes cover identity determination, timer values, and media mixing. **The P25/ISSI side is
   entirely yours to build either way.**
3. **TS 24.379 contains zero occurrences of the string "IWF"**, and so does 24.380. The MCPTT-side
   specs have no interworking-specific procedures — only a reserved Warning-code block (301-350)
   pointing at 29.379. **An MCPTT server that correctly implements 24.379 server-to-server
   interconnection needs no IWF-specific code to talk to an IWF.** All interworking behaviour lives
   on the IWF side of IWF-1.

**Media plane (29.380).** The IWF **terminates and re-originates** floor control; it does not
tunnel it. Each LMR radio is modelled as a synthetic "IWF floor participant" and the IWF runs real
24.380 state machines on its behalf. Critically for reuse: **no new floor messages and no new
fields** — the entire 24.380 set is used verbatim over `m=application <port> udp MCPTT`, with three
features carved out (**multi-talker, ambient listening, functional alias**) and the User ID field
repurposed to carry the mapped MCPTT ID of the LMR talker. Media is passthrough; the IWF forwards
encrypted RTP without decrypting. Transcoding, where needed, is a 23.283 concern (10.7) requiring
the IWF to act as a security gateway.

**The hard interop problem — floor arbitration.** Ranked by how badly the models mismatch:

1. **Arbitration is single-master, fixed per group by configuration.** Whoever homes the group owns
   the floor absolutely (23.283 10.5.3). Get the provisioning wrong and every PTT pays a round trip
   across IWF-1 before the talk-permit tone.
2. **Latency is structural when the LMR side homes the group.** 23.283 10.5.5 step 5 hides an entire
   P25 grant/deny transaction behind the phrase "performs floor arbitration in conjunction with the
   LMR system (not shown)" — and **29.380 clause 11, Timers and Counters, is empty**, so the spec
   gives no budget to design against. You inherit 24.380's T1/T2/T3/T4/T7/T20 and must make the LMR
   round trip fit inside them.
3. **Fan-out multiplication.** Unfiltered, the IWF must synthesise a Floor Taken *per affiliated
   client*. Avoidable by having the IWF affiliate once on behalf of the whole LMR system (10.1.1.2),
   at the cost of per-user affiliation visibility. A real design fork the spec presents without
   recommending.
4. **Override of an unnotifiable talker (23.283 10.5.4)** — written specifically because LMR radios
   exist: "a transmitting radio cannot be signalled that the floor has been taken or revoked", so it
   keeps transmitting. This forces **dual-floor support with two concurrent talkers** and
   configurable per-participant mixing, and 29.380 punts the audio problem ("how the IWF mixes the
   different RTP media stream sources is out of scope").
5. **No queue concept in half-duplex LMR**, priority-model mismatch (29.380 4.1.1.4 lists six inputs
   to effective priority; none map cleanly onto P25 priority/emergency bits), and **late or absent
   talker identity** — if privacy hides the LMR user, the IWF substitutes its own MCPTT ID and all
   LMR traffic collapses to one identity on the MC side.

**Recommendation.** Adopt the IWF **model** as internal architecture; do not treat full IWF
conformance as the goal, and do not build a separate IWF process on day one. Concretely:

- Implement **TS 24.379 server-to-server interconnection roles** (controlling / participating /
  non-controlling) in `mcxas`. This is dual-use — mandatory for the IWF path, valuable regardless,
  and currently the gap.
- Build the P25 gateway as a component presenting an **IWF-1-shaped face**: SIP with
  `application/vnd.3gpp.mcptt-info+xml` (use the 24.379 Annex F.1 schema; do not invent one),
  `m=application <port> udp MCPTT` RTCP-APP floor control, LMR identities namespaced as MCPTT IDs,
  Resource-Priority per RFC 8101. That is a subset of 29.379/29.380, not the whole thing.
- Steal the *decisions* from 23.283 without the document weight: per-group floor homing (10.5.3),
  the local-filtering flag (10.5.5 to 10.5.8), IWF-affiliates-on-behalf-of-LMR (10.1.1.2),
  override-without-revoke (10.5.4), late talker ID (10.13.3).
- **Use Warning codes 301-350** — 24.379 reserves them for interworking and 29.379 uses only
  300/301/302. Free, standards-compatible private error space.
- Read **23.283 clause 10.5.4 and 10.5.5 in full before writing any floor code.** Both break
  assumptions that hold in a floor implementation which has only ever served MC clients.
- Track the ATIS P25 work. A codebase partitioned at IWF-1 can absorb it when it publishes.

Against a full-IWF build, the honest cost argument: 29.379 clause 5.1's normative shall-list alone
drags in TS 24.481 group management client, TS 24.484 profile consumption, TS 33.180 XML protection
plus SPK/GMK/PCK key management with the IWF as encryption endpoint, RFC 8101, RFC 4575 conference
event package (producer and consumer), RFC 6086, the full 24.380 floor control server *and*
participant *and* dual-floor machine, and six connectivity models — a multi-engineer-year effort
before a single P25 packet moves. And parts are unfinished: 29.380 marks the non-controlling role
**FFS**, with an open editor's note on regroup, which is exactly the area a P25 shop most wants.

## A.11 Part A scorecard

| Area | Spec | Verdict |
| --- | --- | --- |
| Architecture / reference points | 23.280 | **2 of ~30** touched, GET-half only |
| MCPTT call control | 24.379 | ~1 of ~20 procedure areas; ~25 post-Rel-13 features absent; FA actively mishandled |
| Floor control | 24.380 | Framing correct; 4 new subtypes and 12 new field IDs absent; no TLV parsing; multi-talker makes current logic actively wrong |
| Group management | 24.481 | Generates documents; cannot be provisioned by standard XCAP writes |
| Config management | 24.484 | Best-conforming corner (AUIDs, MIME, ETags); same write-shadowing defect |
| Identity management | 24.482 | Non-conformant by construction; forbidden token profile |
| Security | 33.180 | Zero implementation; several affirmative anti-patterns |
| MCData | 24.282 / 24.582 | **Absent** — and FRMCS-mandatory |
| MCVideo | 24.281 / 24.581 | **Absent** — not FRMCS-mandatory |
| LMR interworking | 23.283 / 29.379 / 29.380 | **Absent**, and the specs were not previously in the project |

---

# PART B — What FRMCS support would require

## B.1 What FRMCS is, and where an MC server sits in it

FRMCS is the GSM-R successor programme. Its architecture (ETSI TS 103 764 clause 4.2.1) has three
strata:

- **Transport Stratum** — 5GC, 5G NR on RMR harmonised spectrum, QoS, multipath (TS 103 765-1).
- **Service Stratum** — "centered around the 3GPP Mission Critical Communications (MCX) Framework
  and decouples the application from the underlying transport networks" (TS 103 765-2).
- **Railway Application Stratum** — explicitly **not part of FRMCS**.

**The MC application server lives in the Service Stratum, inside the FRMCS Service Domain.** UIC
AT-7800 SRS 6.3.5.3 is the governing requirement: "The FRMCS Service Domain functionalities shall
be realized by a **3GPP MCX server infrastructure (including a SIP Core)** as defined in
[TS 103 765-2]."

So the good news is structural: **an MCX application server is exactly the right kind of product to
be building** if FRMCS is the destination. The bad news is everything about which MCX.

## B.2 The Release-18 pin, and a hard profile

TS 103 765-2 clause 4.1 pins the baseline: MCX architecture "**from 3GPP Release 18 onwards**",
with every 3GPP reference cited at a specific Rel-18 version (23.280 v18.12.0, 24.379 v18.10.0,
24.282 v18.10.0, 24.582 v18.2.0, 24.482 v18.0.1, 24.484 v18.7.0, 33.180 v18.1.0, 23.283 v18.2.0,
and UIC FIS-7970 v2.1.0 as a normative reference).

Then it **profiles MC hard** — this is a strict subset, not a superset:

| MC service | FRMCS mandate (TS 103 765-2 clause 5.1.1) |
| --- | --- |
| **MCPTT** | **"limited to MCPTT ad hoc group call and emergency alert realized through MCPTT ad hoc group call"** |
| **MCData** | **"limited to MCData IPCon and MCData SDS"** — mandatory, co-equal with MCPTT |
| **MCVideo** | **Not mandated.** No entities, no reference points, no procedures. AT-7800 clause 9.2.3: "MCVideo is not in scope." |

Two consequences that reshape the roadmap:

1. **Every FRMCS V2 voice application is an ad hoc group call.** Not a prearranged group call, not
   a chat group. The prearranged-group model that `mcxas` implements — and the XCAP group-document
   machinery behind it — is largely **not what FRMCS uses**. Ad hoc group call is TS 24.379
   **clause 17**, which does not exist in Rel-13 at all.
2. **MCData is not optional.** IPcon (GRE-over-UDP tunnelling of application IP flows, carrying
   ETCS/ATP and ATO traffic) and SDS are both mandatory. That is a second MC service and a
   data-plane component, currently at zero.

Also pinned: **SIP Digest shall be used** as the security mechanism for tight- and loose-coupled
application clients (TS 33.203 Annex N/O), with IMS AKA limited to handhelds; MC service
authorization is a **SIP PUBLISH carrying an OIDC access token** validated by the server
(33.180 5.1.3.2.3); and the CMS/IdMS bootstrap follows 24.484 clause 4.2.2 online case.

## B.3 FRMCS services and their MC mapping

The UIC FRS (FU-7120) never mentions MCPTT or MCData — the mapping is made in AT-7800 and,
normatively, in TS 103 765-2.

| FRMCS application (FRS clause) | Maps to |
| --- | --- |
| Driver-to-controller voice (10.3, 10.4), multi-train (10.5), banking (10.6), trackside maintenance (10.7), shunting (10.8), ground-to-ground (10.10), urgent variants (10.18, 10.19) | **MCPTT ad hoc group call**, on-demand session |
| **Railway Emergency Communication (10.11)** — REC-alert | **MCPTT ad hoc group emergency alert** |
| REC-voice | **MCPTT ad hoc group emergency group call** |
| Point-to-point voice | MCPTT private call — but **TS 103 765-2 explicitly declines to specify normative requirements for it**, while TS 103 792 clause 8 does specify GSM-R point-to-point interworking. A live inconsistency in V1.1.1 |
| ATP/ETCS (11.4), ATO (11.5), telemetry (11.19), transfer of data (11.28) | **MCData IPcon** (GRE-over-UDP, H2H and H2N models) |
| Messaging services (11.27), SMS interworking | **MCData SDS** |
| All video (12.2 to 12.5) | Nothing — the FRS clauses read "To be defined in a later version", and MCVideo is out of scope |

Deferred in this FRS baseline (marked I-Vx): public emergency call (10.9), trackside maintenance
warning (11.7), remote control of engines (11.8), train integrity monitoring (11.13), virtual
coupling (11.16), and all video.

## B.4 The four railway-specific capabilities

These are what make FRMCS more than "MCPTT with a railway logo". All four are implementable in an
MC application server, and none exist in `mcxas` today.

**1. Functional addressing / functional alias as the primary identity.**
FRMCS identifies users by *role*, not by device. The structure is
`Location_label . Identification_label . Equipment_label . Function_label @ OrganisationCode`
(AT-7800 11.6.2.3), with mandated vocabularies per identity class — train identities (Leading
driver, Driver 2-5, conductors, catering, railway security...), controller identities (primary,
secondary, power supply, switchman, emergency manager...), team identities, vehicle and trackside
equipment identities (permanent registrations). AT-7800 11.6.1.1 binds this to 3GPP:
"role based identification shall be based on **Functional Alias** in accordance with [TS 23.280]
clause 8.1.5."

Wildcards are mandatory: `###` means "all" (11.6.2.4). And the server-side behaviour is
non-trivial — a private call addressed to `Secure.Area51.###@db.com` must cause the server to
resolve the matching aliases, **create an ad hoc group, implicitly affiliate the members, and
promote the call to an ad hoc group call**, declining the original private call (SRS Figure 11-6).

Given A.4.1, this is the sharpest point in the whole audit: **FRMCS's primary identity mechanism is
the one the code currently acknowledges with a 200 OK and throws away.**

**2. Server-side participant determination from geography and role.**
UIC FIS-7970 clause 4.3.6.10 requires the criteria to be carried as `<call-participants-criterias>`
inside `<anyExt>` of `<mcptt-Params>` in the `application/vnd.3gpp.mcptt-info+xml` body of the SIP
INVITE, as a comma-separated list. Table 2 criteria include `FRMCS_CallType`,
`FRMCS_UseInitiatingArea`, `FRMCS_ListOfInitiatingArea`, `FRMCS_UseAdressedArea`,
`FRMCS_ListOfAdressedArea`, `FRMCS_AdressedAreaPolygon`, `FRMCS_TargetParticipantList`,
`FRMCS_UseRailwayInfrastructureLocation` (spec's own spellings). The server duty is stated as
"Evaluation upon reception of initiation message", and "the server shall take the **union** of all
Addressed Areas into account".

This is a **geospatial resolver**: match users against named areas and against
**polygons**, then filter by route, direction and speed, and — per FRS 11.1.4.2i — **continuously
re-evaluate eligibility for the duration of the call**, dropping users who leave the area. FRS
8.2.5 requires the location function to answer "which users are currently inside this polygon".
Nothing of this kind exists in the codebase, and it implies a railway-topology data model.

**3. Multi-talker floor control keyed on functional alias.**
AT-7800 21.2.3.1 mandates floor control "based on RTCP signalling (RTCP Application Packets) as
defined in [TS 24.380]" — so the existing floor implementation is the right family. 21.2.4.1
mandates floor request, granted, release, **floor revoke with pre-emptive priority**, and
**identification of the current talker by Functional Alias**. FRS 8.2.3 adds per-user talker
authorisation, per-user talker priority, a configurable **maximum number of simultaneous talkers**,
and initiator-gets-the-floor-first-with-timer.

That is precisely the 24.380 multi-talker feature set from A.5 — the scalar `FloorHolder` must
become a holder set with per-talker timers, plus Floor Taken / Floor Release Multi Talker, plus the
Functional Alias field (017) and List of Functional Aliases (018).

**Caveat worth carrying:** the FRMCS floor **priority scheme itself is not yet defined** —
AT-7800 21.2.6 is an editor's note, and FIS-7970 carries an editor's note that "a change request is
ongoing at 3GPP level in order to achieve the call queueing mechanism needed for FRMCS". Implement
it as configurable policy, not a hard-coded table.

**4. Seven-level railway priority.**
FRS Appendix J defines seven levels, **A to G**: A Railway emergency, B Railway operation high,
C Control-command (safety), D Railway operation medium, E Railway operation normal, F Non-railway
operation, G Any others — used to pre-empt under congestion (the worked example is REC-voice
pre-empting an active ATO session).

Signalling realisation (TS 103 765-2 6.2.5): `<user-requested-priority>` **shall be a 6-digit
non-negative integer**, formatted `[Communication Session Category (4 digits)][Sub-category (2)]`,
and **the Resource-Priority header shall always be set to "Normal"** — an unusual, easily-missed
requirement. Actual enforcement happens on N5/Rx toward the PCF via `afAppId`/`resPrio`, i.e. in
the transport stratum, not here.

*The application-to-level mapping table (Appendix J Table J-1) is column-scrambled in text
extraction; re-read it in the PDF before relying on specific row assignments.*

## B.5 Interfaces, and what the server is actually an endpoint of

System-level FRMCS reference points (TS 103 764 4.3.5): **OBAPP** (on-board app to On-Board FRMCS),
**TSAPP** (trackside app to Trackside Gateway), **OBOM**, **FSOMR**, **FSMPM** (multipath),
**FSNNI** (between FRMCS domains), **FSIWF** (to GSM-R), **FSONI**, **TSCTRL** (VAS controllers).

**The MC application server is an endpoint of only: FSNNI, FSIWF (its IWF-1/IWF-2 legs), and
TSCTRL.** It sits on **SIP-2 (ISC/Ma) behind an FRMCS SIP Core** — which TS 103 765-2 defines as a
*separate element*, either an IMS core or a 23.280-compliant equivalent.

Service-stratum reference points it terminates: SIP-2, HTTP-2, CSC-5, CSC-9, CSC-13, CSC-15,
MCPTT-1/-2/-4/-5/-7, MCData-2/-5/-10, MCData-SDS-1/-2, MCData-IPcon-1/-2.

**FFFIS-7950 is out of scope for this project.** It specifies the OBAPP and TSAPP APIs — the
interface *applications* use to talk to the On-Board FRMCS or the Trackside Gateway. Neither
endpoint is an MC application server. It only becomes relevant if the product also implements a
Trackside Gateway, which is a distinct element (TS 103 765-4).

**FIS-7970 is partially in scope and does constrain this server.** It states it covers only the
Service Stratum and "only the MC service layer requirements", explicitly excluding IMS/SIP core.
Its Table 2 criteria and Table 3 server-internal parameters (`FRMCS_PredefinedParticipantsPer
AdressedArea`, `FRMCS_ExcludeParticipantsDifferentRoute/Speed/Direction`, and others) are direct
MC-server requirements — and several carry `<TBD>` datatypes.

**GSM-R interworking (TS 103 792)** is overwhelmingly IWF-side work, using the same IWF-1/IWF-2
reference points as the LMR interworking in A.10 — a genuinely useful architectural convergence.
What lands on the MC server is small and specific: a configured MCPTT ID representing GSM-R CT5
numbers in the ad hoc criteria; generating the ad hoc group ID; sending floor taken and floor idle
toward the IWF (which converts them to GSM-R unmute/mute); and codec policy — **AMR-WB preferred,
EVS-SWB supported, avoid transcoding**. Functional-number translation and priority mapping are the
IWF's job, not the server's.

## B.6 In scope, adjacent, and out of scope

**A. Implementable in this Go server — the actual FRMCS backlog:**

1. **Ad hoc group calls** (24.379 clause 17: setup 17.3.2.1/17.4.2, release, rejoin, modify
   participants and criteria, participant determination 17.3.6/17.4.6). *The single largest gap.*
2. **REC-alert as ad hoc group emergency alert** (24.379 12.1A and the 6.3.3.1.x set).
3. **Participant-determination engine** — parse and evaluate the FIS-7970 criteria, with area
   unions, polygon intersection, route/speed/direction exclusion, and continuous re-evaluation.
4. **Functional alias management** — activate/deactivate/interrogate/notify (24.379 9A.2.2.2 and
   9A.2.2.3), label-structured parsing, `###` wildcard expansion, temporary vs permanent binding,
   and FA-addressed-private-call to ad-hoc-group promotion.
5. **Role-management configuration surface** (AT-7800 21.3.5) — FA validity timers, never-deactivate
   lists, max active FAs per user, authorised-FA lists. A natural CMS/XCAP extension.
6. **Multi-talker floor control** with per-user priority, pre-emptive revoke, and current-talker
   identification by functional alias.
7. **`<user-requested-priority>` handling** — parse the 6-digit value, map to A-G, drive MC-level
   admission and pre-emption, and always emit `Resource-Priority: Normal`.
8. **Authorisation of communication** from MC user profile data. Note AT-7800 21.4.5.2/.3 wants
   authorisation keyed on FA labels and carries an editor's note that this **is not supported by
   MCX procedures** — i.e. a documented proprietary extension.
9. **Location reporting configuration/request/report** (24.379 13.2.2/13.2.3/13.2.4) feeding item 3.
10. **MCData SDS**, then **MCData IPcon** — bounded, server-side, and mandatory.
11. Recording and logging hooks; MC service group ID formats for ad hoc vs predefined groups.

**B. Separate elements it must talk to:** FRMCS SIP Core / IMS (plus IBCF/TrGW for FSNNI), IdMS,
CMS, KMS, LMS, functional alias management server, MCPTT and MCData user databases, SIP database,
Diameter proxy, 5GC PCF/NEF, MC gateway server, the IWF, the On-Board FRMCS and Trackside Gateway
(which host MC clients for loose-coupled applications), and VAS controller equipment over TSCTRL.

Of the existing subsystems, the **XCAP config/group management is the one with a natural FRMCS
home** — it could plausibly become the CMS (CSC-4/CSC-5 per 24.484). The REST OAM API has no FRMCS
counterpart at all.

**C. Out of scope for this project entirely:** the whole Transport Stratum (5GC, NR, RMR spectrum,
multipath, QoS enforcement); UE capabilities (TS 103 765-5); OBAPP/TSAPP and all of FFFIS-7950;
OBOM/FSOMR; the On-Board FRMCS / TOBA; the Trackside Gateway and VAS; **arbitration** (AT-7800
21.5.1.1 makes it tight-coupled-only and VAS-configured; TS 103 765-2 6.2.7 explicitly declines to
specify it); location *acquisition* (GNSS, cell ID — the UE produces it, the server only consumes
and matches); GSM-R side elements (MSC, GCR, MGCF, MGW, IP-SM-GW) and the IWF-g1/g2/g5 legs; and
MCVideo.

## B.7 Maturity caveats

FRMCS is a moving target and several of these documents are first editions dated January 2026.
Anything built against them should be built to absorb change:

- **No normative MCPTT private call** in TS 103 765-2 (explicit NOTE), despite TS 103 792
  specifying GSM-R point-to-point interworking — an unresolved inconsistency.
- **MCData File Distribution** (6.2.4), **arbitration** (6.2.7) and **network-initiated
  deregistration** (6.3.3) are all explicitly unspecified.
- **IWF-3** is required by TS 103 765-2 5.3.2 but declared unused by TS 103 792 5.2.3.
- **CSC-2 / group management server** is required of VAS controllers by TS 103 765-4 clause 7.2 but
  absent from TS 103 765-2's mandatory entity list.
- **FIS-7970** server-side call-control parameters carry `<TBD>` datatypes and V3 deferrals; call
  queueing depends on an in-flight 3GPP change request.
- The FRMCS **floor priority scheme** is an editor's note, not a specification.
- **FSNNI out-of-band certificate exchange** is left to bilateral operator agreement.
- UIC documents distinguish **V2 (current baseline)** from **V3 (TSI target, enabling GSM-R
  migration)**; a number of the capabilities above are marked M-V3 or I-Vx and are not in the
  validated V2 minimum set.

---

# PART C — Combined assessment

## C.1 Where this leaves the project

`mcxas` is a working demonstrator of a prearranged MCPTT group call against one vendor's client.
Both questions in this audit converge on the same three-sentence answer:

- **On the MCX side**, the gap is not a list of features — it is a release generation, an
  architecture (fused SIP endpoint versus AS-behind-a-SIP-core), a missing security plane, and two
  of three services.
- **On the FRMCS side**, the product category is right and the destination is reachable, but FRMCS
  needs a **Rel-18 MC server doing ad hoc group calls with server-side geographic and role-based
  participant determination, multi-talker floor control, and MCData** — of which the code today has
  the floor-control *framing* and nothing else.
- **On the P25/ISSI plan**, the most valuable finding is that 3GPP already specifies this bridging
  problem, the specs are in your library, and P25 is the one major LMR technology whose companion
  mapping is still unpublished.

## C.2 The convergence worth exploiting

The three directions in play are less divergent than they look:

- **P25/ISSI** and **GSM-R interworking** both terminate on the MC server at **IWF-1/IWF-2**, using
  the same reference points and the same "peer interconnected MC system" model. Architecture built
  for one serves the other.
- **Functional alias** is simultaneously a Rel-19 MCPTT gap (A.4.1), the FRMCS primary identity
  (B.4.1), and the natural vehicle for mapping LMR role-based identities (23.283 clause 8.1 names
  functional aliases for exactly this).
- **Multi-talker floor control** is a Rel-19 gap (A.5), an FRMCS mandate (B.4.3), and directly
  relevant to the LMR override problem where two radios transmit at once (23.283 10.5.4).
- **Ad hoc group calls** are the FRMCS voice model *and* the mechanism TS 103 792 uses to bridge
  GSM-R group calls.

Four work items sit at the intersection of all three roadmaps. That is where effort compounds.

## C.3 Suggested ordering

Nothing here is a commitment — it is the order in which the dependencies actually fall.

**Phase 0 — make the current thing sound.** The items from
[AUDIT-2026-08-11.md](AUDIT-2026-08-11.md): a `.gitignore` (the compiled binary and 8,629
`node_modules` files are committed), the committed lab identifiers and DSN password, the systemd
unit running as root, SIP input size caps, store transactions and indexes, and the SIP transaction
layer. None of this is spec work; all of it is prerequisite to any of the below.

**Phase 1 — decide the release target and the architectural posture.** Rel-13-with-MCOP and
Rel-18-for-FRMCS are different products. If FRMCS or ISSI is the destination, the fused
SIP-endpoint design and the prearranged-group model both need to change, and it is cheaper to
decide that before more code accretes.

**Phase 2 — the compounding four**, in this order:
1. TS 24.379 **server-to-server interconnection roles** (controlling / participating /
   non-controlling). Prerequisite for IWF, GSM-R, FRMCS interconnection, and regroup.
2. **Functional alias** (24.379 9A) — and fix the PUBLISH/SUBSCRIBE event collision first, since it
   is currently silently corrupting client state.
3. **Ad hoc group calls** (24.379 clause 17).
4. **Multi-talker floor control** (24.380), which requires first building the real TLV parser,
   timer set and state machine the current floor code lacks.

**Phase 3 — pick a destination and specialise:** the P25 gateway behind an IWF-1-shaped seam; or
the FRMCS participant-determination engine plus MCData SDS/IPcon; or MCVideo if the RTCP-APP
codebase is being generalised anyway.

**Security is not a phase.** TLS, real token validation, and the ability to turn off the IdMS shim
are prerequisites for anything that touches a real network, and the shim as written will hand an
MCPTT identity to any unauthenticated caller.

## C.4 One-line answer

**A)** Nearly everything: measured against Rel-19 the code implements one narrow path through one
of three MC services, on a six-release-old baseline, with two of ~30 reference points, no security
plane, and a functional-alias handler that silently discards valid signalling.
**B)** FRMCS is reachable and the product category is correct, but it requires a Rel-18 MC server
built around ad hoc group calls, functional aliases, geographic participant determination,
multi-talker floor control and mandatory MCData — a different system from the one that exists,
sharing roughly the floor-control framing and the XCAP configuration machinery.
