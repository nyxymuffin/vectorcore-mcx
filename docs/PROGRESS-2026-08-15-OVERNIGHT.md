# Overnight autonomous run — 2026-08-15

Continuation of the MCX compliance plan (see
PLAN-MCX-COMPLIANCE-AND-FRMCS-2026-08-12.md). MCX-only per instruction; no
FRMCS or IWF/ISSI work. Every slice was implemented against the extracted
Rel-19 spec text, gated with `check-race`, and committed with clause
citations and explicit deferrals.

## Completed this run

| Commit | Phase | Scope |
|---|---|---|
| 3a251a6 | 2c | Ad hoc group calls (TS 24.379 clause 17): resource-lists participants, generated adhoc identity, 186/187/189 rejections, adhoc member legs |
| 7073fc4 | 2d | Multi-talker floor control (TS 24.380): real TLV parser (8.1.3), group-wide arbitration, Floor Taken to peers with talker set, Floor Release Multi Talker (8.2.14), per-group multi_talker config |
| dd97577 | 3 | XCAP conformance (RFC 4825/TS 24.481): node selectors, conditional ops (304/412), xcap-error bodies, xcap-caps, byGroupID, supported-services, FunctionalAliasList in profile, generated-AUID writes refused |
| eee3dd4 | — | Private call (24.379 clause 11.1.1): callee actually invited, caller answered after callee's 200, 145/146 and unbound-callee 404 |
| 9520497 | — | Chat group calls (24.379 clause 10.1.2): no fan-out, shared session identity, implicit affiliation, 486/122, on-network-invite-members in group doc |
| c62ab6d | — | Emergency / imminent peril group calls: 6.3.3.1.13.2 authz stand-ins, 6.3.3.1.14 rejection body, in-progress states, Resource-Priority (6.3.3.1.19) on member legs |
| 550e2fe | — | MCData standalone SDS (24.282 clause 9.2.2): one-to-one, group and ad hoc SDS distribution, 199/204/116/120/163/198 rejections, 202 Accepted |
| 994777c | — | Floor request queueing (24.380 clause 6.3.4.4.2 case b): mc_queueing, Queue Position Info, grant-on-release |

## Carried forward (each cited in its commit)

TNG1/TNG2/TNG3 and per-talker T1/T2/T20 timer supervision; RFC 4028 session
refresh handling; first-to-answer calls; emergency alert MESSAGEs and
re-INVITE upgrade/cancel (incl. the 6.3.3.1.8 UPDATE); media anchoring and
CANCEL relay for remotely homed groups; node-selector PUT/DELETE and
change-triggered xcap-diff NOTIFY (RFC 5875); KMS/SRTP; criteria-based
participant determination (FRMCS scope); MCData dispositions, clause 11.1
limits, media-plane SDS.

## Build box

172.25.221.105 synced through c62ab6d (994777c still pending — the IPS
between 172.16.x and 172.25.x began resetting/refusing connections mid-run;
a detached `make check-race` was launched there but its completion is
unverified, log at /tmp/race.log). Local `mingw32-make check-race` was green
for every commit.

## Morning session (supervision phase, one slice at a time)

| Commit | Scope |
|---|---|
| 07e4a40 | RFC 4028 session timer supervision: refresh handling on re-INVITE/UPDATE, reaper BYEs both directions |
| 404cfab | TNG3 group call timer (group max_duration_seconds / <on-network-maximum-duration>) + private and ad hoc call duration timers |
| bb82c38 | TNG2 in-progress emergency group call timer (sip.emergency.group_time_limit_seconds, advertised as <group-time-limit>) |
| 0f3d012 | Floor timer T1 (End of RTP media): silent talkers lose the floor; media.floor_t1_seconds |
