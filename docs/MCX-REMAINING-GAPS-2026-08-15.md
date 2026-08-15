# MCX remaining conformance gaps — 2026-08-15

Consolidated from the per-commit deferral ledgers (each item was cited against
its clause when deferred) and re-verified against the 2026-08-11 gap analysis.
Scope: MCPTT (TS 24.379), floor control (TS 24.380), GMS (TS 24.481),
CMS (TS 24.484), MCData SDS (TS 24.282), security (TS 33.180).
Out of scope by instruction: IWF/ISSI (TS 29.379 family). MCVideo (TS 24.281)
was never in the audited scope — flagged below as a scope question.

## A. Call control, TS 24.379 — remaining

| Item | Clause(s) | Notes |
|---|---|---|
| Emergency alert | 6.3.3.1.11/.12/.18/.20, 12.1 | alert-ind handling, SIP MESSAGE notifications to members, warning 149 + SIP INFO follow-up |
| Emergency upgrade/cancel via re-INVITE | 6.3.3.1.15, 11.1.1.4.3–.6 | in-call upgrade to emergency/imminent peril and cancellation; TNG2 downgrade re-INVITE/MESSAGE fan-out (6.3.3.1.16 steps 2–3) |
| Resource-Priority UPDATE toward initiator | 6.3.3.1.8 | when the INVITE lacked the R-P header |
| Broadcast group call | 4.1.2, 10.1.1.4.2 | broadcast-ind; one-way transmission semantics |
| Acknowledged group setup (TNG1) | 6.3.3.3 | on-network-required members must answer before the 200 |
| Rejoin / late entry | 10.1.1.4.3 | joining an ongoing prearranged session |
| Pre-established sessions | clause 8, REFER | REFER is advertised but 405s; whole MCPC leg of 24.380 clauses 8.3/9 with it |
| PRACK / 100rel | 6.3.3, RFC 3262 | advertised in Allow, unhandled |
| First-to-answer CANCEL of ringing losers | 11.1.1.4.2 step 8 b/c | late-answer BYE fallback (8 d) is in place |
| Private call forwarding | 11.1.1.3.2 | CFU/CFNP lists, warnings 174/175 |
| Private call profile authz | 11.1.1.3.2 steps 8/10 | warnings 127/159 need per-user profile fields |
| Call-to-functional-alias | 9A.2.2.2.8, 11.1.1.4.2 steps 8a/12 | FA→MCPTT-ID resolution, SIP 300 Multiple Choices |
| FA determination/take-over | 9A.2.2.2.x remainder | FA in-call binding, take-over of an active alias |
| Affiliation completeness | 9.2.2.2 | N2 limit (warning 102), affiliation expiry, remote-change (9.2.2.4), simple-filter evaluation |
| Conference event package | 10.1.3 | SUBSCRIBE Event: conference currently 489 |
| Location reporting | clause 13 | mcptt-location-info over MESSAGE/PUBLISH |
| Regroup / TGI | clause 16, warnings 148/163/167 | group regroup, temporary group identities, non-controlling function |
| MBMS bearer announcement | 14.2 | needs eMBMS bearers — candidate for explicit N/A |
| Min-SE / 422 negotiation | RFC 4028 §5 | supervision itself is done |
| Remote-controlling completeness | 6.3.2.1.x | CANCEL relay, media anchoring for relayed sessions |
| Feature-tag validation on inbound INVITE | 6.3.3.1.x step 2 | Accept-Contact g.3gpp.mcptt/ICSI checks, isfocus-in-Contact rejection |

## B. Floor control, TS 24.380 — remaining

| Item | Clause(s) | Notes |
|---|---|---|
| Timers T2/T3/T4/T7/T8/T9/T20 + C7/C20 | clause 11, 6.3.4/6.3.5 | only T1 runs today; T20 = Floor Granted re-send, T8 = revoke supervision, T7/C7 = Idle repetition |
| Floor Granted field completeness | 8.2.5 | header SSRC should be the server's (we echo the requester's); add Floor Priority + Audio SSRC of Granted Participant (field 14) |
| Floor Deny Reject Cause | 8.2.6.2 | bare deny today; needs cause #1–#7 values |
| Floor Idle / Taken Message Sequence Number | 8.2.3.10 | plus Idle/Taken repetition toward the group |
| Floor Revoke | 8.2.10 | revoke message itself (T1 path currently jumps straight to idle); pending-revoke state |
| Pre-emptive priority arbitration | 6.3.4.4.7, 4.1.1.4 | revoke-lowest / audio cut-in on pre-emptive requests; priority-ordered queue insertion |
| Floor Ack handling | 8.2.13 | ack-request bit is parsed but never acted on |
| Queued Floor Requests message | 8.2.15 | list of queued users toward clients |
| Dual floor control | 6.3.6 | override speaker alongside normal speaker |
| Granted-party tracking by MCPTT ID | 8.2.3.6 | DB holder is ssrc:%08x; wire messages already carry the MCPTT ID |
| Per-session floor ports | 4.3, 14 | one global floor port, matched by source address |
| MCPC pre-established session control | 8.3, 9 | with clause 8 of 24.379 |
| MBMS subchannel control (MCMC) | 8.4, 10 | candidate for explicit N/A |

## C. CMS / GMS / IdMS

**CMS (TS 24.484)** — serving side is in good shape: generated ue-init-config,
ue-config, user-profile (with FunctionalAliasList), service-config
(emergency-call, resource priorities), XCAP node-selector GET, conditionals,
xcap-caps, xcap-error, XSD-validated on the box. Remaining:

- Node-selector PUT/DELETE (partial document mutation, RFC 4825 8.2.3/8.2.5) —
  currently refused with cannot-insert.
- Change-triggered xcap-diff NOTIFY (RFC 5875) — subscribers get the initial
  NOTIFY only; document changes don't push.
- xmlns() namespace-binding evaluation in node selectors (local-name matching
  today).
- HTTP authorisation on XCAP (TS 24.482: bearer access token on CSC-4/CSC-8) —
  the XCAP endpoints are currently unauthenticated.
- Client-managed documents: PUTs to generated AUIDs are refused by design
  (profiles/groups live in the DB, managed via the API). Conformant
  client-side document management would need real PUT flows; decision needed
  on whether the DB-is-authoritative model stands.

**GMS (TS 24.481)** — generated group documents now carry supported-services,
on-network-invite-members, multi-talker-control, allow-MCPTT-emergency-call,
on-network-maximum-duration, byGroupID paths. Remaining:

- Group document write path (create/modify/delete by authorised users per
  clause 6.2/6.3) — same DB-is-authoritative decision as CMS.
- Document subscriptions with change NOTIFY (with the RFC 5875 item above).
- GKTP documents (group key transport, 33.180) — KMS scope.
- Regroup/preconfigured-group document elements (with the clause 16 item).
- Group document elements not yet generated: on-network-disabled,
  preconfigured-group-use-only, entry-level multi-talker-allowed,
  user-priority/participant-type richness beyond the membership role.

**IdMS (TS 24.482 / 33.180 clause 5.1)** — what exists is a development shim:
auth/token endpoints and a JWKS the SIP side validates against (ES256-only,
alg:none refused, issuer pinning). It is not a real OpenID Connect provider:
no user authentication, no consent, no refresh tokens, no scopes
(3gpp:mc:ptt service scopes), no PKCE. Two viable paths:

1. Integrate an external IdM (Authentik is already deployed in the homelab,
   speaks OIDC, can sign with EC keys) and point sip.auth.trusted_jwks_file /
   trusted_issuer at it. The shim stays for offline dev.
2. Grow the shim into a minimal conformant IdMS.

Recommendation: option 1 — 33.180 explicitly models the IdMS as a standard
OIDC provider, and running a hardened one is better than building one.

## D. MCData, TS 24.282 — remaining

Disposition notifications (Conversation/Message ID correlation), clause 11.1
authorisation and size limits (warnings 208/217/218), functional-alias
targets with SIP 300, media-plane SDS (9.2.3), file distribution (FD),
enhanced status, conversation management.

## E. Security, TS 33.180 — remaining

KMS and key management (CSK/GMK/PCK distribution via MIKEY-SAKKE), SRTP/SRTCP
media protection, signalling-plane XML confidentiality/integrity protection,
GKTP as above, HTTP-1 bearer authorisation (listed under CMS). Access-token
validation for service authorisation is done.

## Scope decisions (Nyx, 2026-08-15)

1. MCVideo (TS 24.281): OUT OF SCOPE.
2. MBMS/eMBMS (24.379 §14.2, 24.380 §8.4/10): N/A — the VectorCore
   ecosystem (github.com/vectorcore-mobile) has no BM-SC, MBMS-GW or MCE,
   the three components eMBMS requires; there is nothing to announce a
   bearer on. Revisit only if those ever exist.
3. XCAP writes: FOLLOW THE SPEC — implement authorised client document
   management (create/modify/delete writing back to the store), HTTP bearer
   authorisation per TS 24.482, and change-triggered xcap-diff NOTIFY.
4. IdMS: FOLLOW THE SPEC — grow the shim into a conformant OIDC provider
   per TS 24.482 / 33.180 (user authentication, scopes, PKCE, refresh);
   the trusted-JWKS knob stays so an external IdM remains possible.

## F. Open question for Nyx: TrK key wrap length (TS 33.180)

The KMS provisioning interface is implemented (Annex D: init, keyprov,
certcache, cert) and issues real ECCSI and SAKKE key material. What is not
implemented is the clause D.2.2 security extension, where the key material
in a KmsKeySet is wrapped under the shared 256-bit Transport Key instead of
being carried as plain hexBinary.

The blocker is a length mismatch in the specification itself. Clause 9.3.4.2
and every example in clause D.3.4 identify the wrapping algorithm as
'http://www.w3.org/2001/04/xmlenc#kw-aes256', which clause 9.3.4.2 states is
"the AES-256 key wrap algorithm as defined in RFC 3394 [34]". RFC 3394
requires the plaintext to be a whole number of 64-bit blocks. The three
values that need wrapping are not:

  UserDecryptKey    (SAKKE RSK)  257 octets  = 0x04 || x || y, 128-octet
                                               coordinates (RFC 6508 cl. 4)
  UserPubTokenPVT   (ECCSI PVT)   65 octets  = 0x04 || x || y, 32-octet
                                               coordinates (RFC 6507 cl. 3.2)
  UserSigningKeySSK (ECCSI SSK)   32 octets  — this one does wrap cleanly

So two of the three cannot be wrapped by the named algorithm as written.
The plausible readings are (a) drop the constant 0x04 uncompressed-form
prefix before wrapping, giving 256 and 64 octets, since a receiver knows
the form and can restore it; (b) use AES key wrap with padding (RFC 5649),
which handles arbitrary lengths but is a different algorithm than the one
the URI names; or (c) some deployment convention not written down here.

This is a wire format, so guessing it wrong means key material no client can
unwrap. Until it is settled the interface carries key material as
KeyContentType hexBinary over the mandatory HTTPS of clause D.1, which is
conformant for non-public-safety use; clause 5.3.3 step 2 says the TrK
wrapping is what public safety use requires. Worth checking against a real
KMS implementation or an MCX interoperability profile before choosing.

Also still open in this area: the optional HMAC-SHA256 XML signature over
KMS requests and responses (clause D.2.2), KMS Lookup and Redirect
(D.2.7/D.2.8, D.4), and the MIKEY-SAKKE key distribution over SIP
(clauses 5.4 to 5.7). That last one needs the Tate-Lichtenbaum pairing of
RFC 6508 clause 3.2, which the KMS itself does not need but an MCX Server
does, because CSK upload requires the server to decrypt a SAKKE payload
addressed to its own MDSI identity.

## G. Second open question: MIKEY SIGN payload length (TS 33.180 E.1.2)

Clause E.1.2 says of every MIKEY-SAKKE message: "The signature (S type)
field shall be of type '2' (ECCSI) and the Signature length field shall be
'32', indicating a signature length of 32 bytes (i.e. 256 bits)."

S type 2 is the ECCSI signature of IETF RFC 6507, and RFC 6507 clause 3.3
fixes an ECCSI Signature at r || s || PVT = 4N+1 octets, which for the
P-256 profile that RFC 6509 clause 2.1.1 mandates is 129 octets. The r and
s components alone are 64. A 32-octet field cannot carry the signature the
same sentence calls for.

Unlike the TrK question in section F there is only one self-consistent
reading, so the implementation writes 129 and the rest of the message
follows the referenced RFCs. Worth confirming against a real MCX
implementation before interop testing, because a peer that took the
sentence literally would emit something no one can verify.

Also deferred in the MIKEY layer: crypto session maps (CS# greater than 0
with the GENERIC-ID map of RFC 6043 clause 6.1.1) - the default security
profiles of Annexes E.2.2, E.3.2 and E.4.2 use the empty map, which is
what is implemented; the Security Properties payload is parsed past rather
than interpreted. The SAKKE-to-self extension (Annex E.5), the key
parameter payload (Annex E.6) and identity hiding (Annex E.7) are not
implemented.
