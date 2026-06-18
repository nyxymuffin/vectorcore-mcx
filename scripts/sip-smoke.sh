#!/usr/bin/env bash
set -euo pipefail

host="${1:-127.0.0.1}"
port="${2:-5060}"
realm="${3:-ims.mnc435.mcc311.3gppnetwork.org}"

psi="sip:mcptt-as@${realm}"
impu="sip:311435300070581@${realm}"
mcptt_id="sip:16752012881@${realm}"
group="sip:DEMO_group@${realm}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require nc
require socat

echo "== TCP OPTIONS =="
printf 'OPTIONS %s SIP/2.0\r\nVia: SIP/2.0/TCP 10.90.250.50;branch=z9hG4bKtop\r\nVia: SIP/2.0/UDP 192.168.105.116:37457;branch=z9hG4bKue\r\nFrom: <%s>;tag=fromtcp\r\nTo: <%s>\r\nCall-ID: smoke-tcp-options\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' "$psi" "$impu" "$psi" \
  | nc -w 2 "$host" "$port"

echo
echo "== UDP OPTIONS =="
printf 'OPTIONS %s SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5099;branch=z9hG4bKudp\r\nFrom: <%s>;tag=fromudp\r\nTo: <%s>\r\nCall-ID: smoke-udp-options\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' "$psi" "$impu" "$psi" \
  | socat -T2 - "UDP:${host}:${port}"

publish_body=$(cat <<EOF
--smoke
Content-Type: application/vnd.3gpp.mcptt-info+xml

<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params><mcptt-client-id type="Normal"><mcpttString>${mcptt_id}</mcpttString></mcptt-client-id><mcptt-request-uri type="Normal"><mcpttURI>${mcptt_id}</mcpttURI></mcptt-request-uri></mcptt-Params></mcpttinfo>
--smoke
Content-Type: application/poc-settings+xml

<poc-settings xmlns="urn:oma:params:xml:ns:poc:poc-settings"><entity id="smoke"><am-settings><answer-mode>automatic</answer-mode></am-settings></entity></poc-settings>
--smoke--
EOF
)

echo
echo "== TCP PUBLISH multipart =="
printf 'PUBLISH %s SIP/2.0\r\nVia: SIP/2.0/TCP 10.90.250.50;branch=z9hG4bKpub\r\nFrom: <%s>;tag=frompub\r\nTo: <%s>\r\nCall-ID: smoke-publish\r\nCSeq: 1 PUBLISH\r\nEvent: poc-settings\r\nContent-Type: multipart/mixed;boundary=smoke\r\nContent-Length: %d\r\n\r\n%s' "$psi" "$impu" "$psi" "${#publish_body}" "$publish_body" \
  | nc -w 2 "$host" "$port"

invite_body=$(cat <<EOF
--invite
Content-Type: application/sdp

v=0
o=organization 1983 678901 IN IP4 192.168.105.116
s=-
c=IN IP4 192.168.105.116
t=0 0
m=audio 37514 RTP/AVP 0
a=sendrecv
m=application 44396 udp MCPTT
a=fmtp:MCPTT mc_priority=7;mc_granted;mc_implicit_request
--invite
Content-Type: application/vnd.3gpp.mcptt-info+xml

<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params><session-type>prearranged</session-type><mcptt-request-uri type="Normal"><mcpttURI>${group}</mcpttURI></mcptt-request-uri><mcptt-client-id type="Normal"><mcpttString>${mcptt_id}</mcpttString></mcptt-client-id><alert-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></alert-ind></mcptt-Params></mcpttinfo>
--invite--
EOF
)

echo
echo "== TCP INVITE multipart =="
printf 'INVITE %s SIP/2.0\r\nRecord-Route: <sip:mo@10.90.250.50;lr=on>\r\nVia: SIP/2.0/TCP 10.90.250.50;branch=z9hG4bKinvtop\r\nVia: SIP/2.0/UDP 192.168.105.116:37457;branch=z9hG4bKinvue\r\nFrom: <%s>;tag=frominv\r\nTo: <%s>\r\nContact: <sip:311435300070581@192.168.105.116:37457;transport=udp>\r\nCall-ID: smoke-invite\r\nCSeq: 1 INVITE\r\nP-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt\r\nContent-Type: multipart/mixed;boundary=invite\r\nContent-Length: %d\r\n\r\n%s' "$psi" "$impu" "$psi" "${#invite_body}" "$invite_body" \
  | nc -w 2 "$host" "$port"
