# Phase 2a Design — Participating / Controlling Function Split

**Date:** 2026-08-14
**Status:** proposal, awaiting review before implementation
**Spec basis:** TS 24.379 clauses 6.3.2 (participating), 6.3.3 (controlling),
6.3.5/6.3.6 (group doc retrieval, affiliation check), 4.5 (MCPTT session
identity), 4.4.2 (warning texts); TS 23.379 clause 7 (functional model).

---

## 1. What is wrong today, stated precisely

`sip.go` implements one fused AS that plays both roles at once and neither
correctly:

1. **The 200 OK lies.** An inbound group INVITE is answered 200 immediately;
   member legs go out *after* the response (sip.go, `handleInvite` →
   `sendGroupCallNotifications` after `respondTagged`). Per 6.3.3.2.3.2 the
   controlling function answers the originator only once the call is actually
   established toward the group. Every commencement-mode behaviour builds on
   this ordering, so nothing above it can be right until it is fixed.
2. **No role boundary exists**, so there is nothing for a second MC system, an
   IWF (the P25 path), or a GSM-R gateway to interconnect *with*. All three
   speak MCPTT-3 toward a controlling or participating function — which the
   code cannot present because the roles are not separable.
3. **Admission checks membership, not affiliation** (6.3.6), there is no group
   document retrieval step (6.3.5), no MCPTT session identity / `isfocus`
   Contact (4.5), no TNG1/TNG3 timers, and rejections carry no Warning texts.
4. **Outbound requests have no client transactions.** RX INVITEs are written
   once to the wire; no Timer A/E retransmission, no Timer B/F timeout, no
   branch-matched response handling. Over UDP this makes every outbound leg
   unreliable exactly when the network is imperfect.

## 2. Target model

One process, two explicit roles, an internal interface between them shaped
like MCPTT-3 so the transport can later become real SIP without redesign:

```
            inbound INVITE (originating leg)
                      │
              ┌───────▼────────┐    findRoute(group)     ┌────────────────┐
              │ participating   │ ──────────────────────▶ │ controlling    │
              │ function        │   in-process today,     │ function       │
              │ (serves users)  │   SIP later             │ (owns groups)  │
              └───────┬────────┘                          └───────┬────────┘
                      │ 183/ringing/200 per controlling verdict   │
                      ▼                                           ▼
                originator UE                          member legs (RX INVITEs,
                                                       client transactions,
                                                       TNG1 acknowledged setup)
```

- **`internal/sip/participating`** — serves *users*: terminates the
  originating leg, identifies the served user, applies per-user authorisation,
  forwards the call toward the controlling function of the target group, and
  relays the verdict back to the originator. Also owns the terminating side:
  delivering RX INVITEs to registered users.
- **`internal/sip/controlling`** — owns *groups*: group document + affiliation
  admission (6.3.5/6.3.6), allocates the MCPTT session identity and answers
  with `Contact: <session-id>;isfocus` (4.5), invites affiliated members,
  runs TNG1 (acknowledged call setup) and TNG3 (group call inactivity), and
  answers the originating leg only per 6.3.3.2.3.2. Emits Warning texts
  119/120/121 on rejection.
- **The seam between them** is a Go interface whose methods mirror the
  MCPTT-3 exchanges (originating session request → verdict; member invite →
  progress/answer). Local groups bind to an in-process implementation; a
  remote implementation speaking real SIP arrives in a later slice with no
  change to either role. This is exactly where an IWF plugs in.
- **Non-controlling function: deferred.** It exists for regroup/temporary
  groups (clause 16/10.1.1.5), which are Phase 3+ scope. The seam leaves room.

## 3. Decisions proposed

**D1 — Client transactions first, as their own slice.** Timer A/E
retransmission, Timer B/F timeout, branch-matched responses for outbound
requests, symmetric with the Phase 0 server-transaction table. Self-contained,
no behaviour change to inbound handling, and everything after it depends on
outbound legs being reliable. This is also the Phase 0 carry-forward closed.

**D2 — Introduce the profile seam now, minimally.** Phase 4 planned
`internal/profile` as a no-op; 2a is the code it hooks. Writing the
controlling function against `profile.SessionPermitted` +
`profile.DetermineParticipants` from day one (with the MCX implementation
simply returning affiliated members) costs almost nothing and avoids
retrofitting the exact functions FRMCS overrides. The rest of the Profile
interface waits for Phase 4 as planned.

**D3 — Group homing by configuration, resolved per group.** A `group_homes`
concept: every group is either homed locally (controlling function in this
process) or at a peer URI (future). Today everything homes locally; the
lookup exists so slice 5 changes data, not code. This mirrors 23.283 10.5.3,
where per-group homing is also what decides floor-control mastery for
interworking later.

**D4 — `sip.mode` lands last, not first.** The registrar/standalone question
is orthogonal to the role split: roles concern INVITE processing, mode
concerns REGISTER termination. Sequencing mode last means every intermediate
state keeps the current demo flow working (standalone + roles). The
application_server mode then only changes who terminates REGISTER and how
routes are learned.

**D5 — TNG1/TNG3 configurable with spec-shaped defaults**, under `sip.timers`
(TNG1 acknowledged-setup, TNG3 group inactivity). FRMCS later tunes these; the
base uses 24.379 Annex B defaults.

## 4. Commit sequence

Each slice is independently green (`check-race` passes) and reviewable:

1. **Client transactions** (`internal/sip/transaction.go` grows a client
   half): retransmission, timeout, response matching. Outbound call sites
   switch from fire-and-forget `sendOutbound` to transacted sends.
2. **Role extraction, no behaviour change**: `handleInvite`'s group path moves
   behind the participating/controlling interfaces, in-process binding,
   identical wire behaviour, snapshot tests pinning it.
3. **Controlling function conformance**: ordering fix (member legs before the
   originator's 200 per 6.3.3.2.3.2, driven by TNG1), affiliation-based
   admission with Warning 119/120/121, session identity + `isfocus`, TNG3.
   This is the slice where wire behaviour deliberately changes.
4. **Participating function conformance**: served-user authorisation on the
   originating leg, terminating-leg delivery (RX INVITE) via the client
   transactions, answer-mode honoured from stored poc-settings instead of the
   removed hardcode.
5. **Remote controlling binding**: the seam's SIP implementation — outbound
   INVITE toward a peer's PSI carrying mcptt-info + SDP, so a group homed at
   another MCPTT system (or an IWF) actually works. MCPTT session identity
   routing on the return path.
6. **`sip.mode: application_server`**: third-party REGISTER consumption per
   7.3.1 (parse `message/sip` body, bind IMPU↔MCPTT ID), standalone kept as
   configured default until an IMS core exists in the lab.

Slices 1–2 are refactoring-grade risk. Slice 3 is the conformance payoff and
the first observable behaviour change. Slices 5–6 are where the P25/FRMCS
futures attach.

## 5. Out of scope for 2a

Non-controlling function, pre-established sessions, emergency/priority
(Phase 2's later slices), functional alias (2b), ad hoc groups (2c),
multi-talker (2d), KMS/SRTP (carried), MBMS.

## 6. Risks

- **Slice 3 changes observable timing**: the originator's 200 now waits for
  member admission (bounded by TNG1). Any client assuming instant answer will
  feel it; that assumption is exactly what 2.0 removed support for.
- `sip.go` shrinks but its INVITE paths are heavily interwoven with dialog
  and store writes; slice 2's "no behaviour change" claim is enforced by
  snapshot tests over full wire exchanges, not by review alone.
- The in-process seam must not leak Go-only conveniences (shared pointers into
  store state) or slice 5 becomes a rewrite; the interface passes values.
