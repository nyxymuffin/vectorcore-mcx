package sip

import (
	"context"
)

// The participating/controlling function split of TS 24.379 clauses 6.3.2 and
// 6.3.3 (design docs/DESIGN-2A-INTERCONNECTION-ROLES.md, slice 2).
//
// The controlling function owns a group: admission, member legs, and the
// group-call lifecycle. The participating side (today still the body of
// handleInvite) reaches it only through this interface, whose operations are
// shaped like the MCPTT-3 exchanges so that a later binding can speak real
// SIP toward a group homed at another MC system or an IWF without either side
// changing (decision D3: homing is per group, resolved at call time).
//
// This slice deliberately changes no wire behaviour: the sole implementation
// delegates to the pre-existing code paths, and the group-call snapshot tests
// pin the exchanges byte-for-byte around the move.

// originatingGroupCall is what the controlling function needs to know about
// an originating leg. Values only - the seam must stay serialisable so the
// remote binding is a data change, not a redesign.
type originatingGroupCall struct {
	CallID       string
	InitiatorURI string
	GroupURI     string
	SDP          sdpInfo
}

// admissionVerdict is the controlling function's decision on an originating
// leg. Status, Reason and Warning are meaningful only when Admitted is false;
// Warning carries the TS 24.379 clause 4.4.2 warning text for the response.
type admissionVerdict struct {
	Admitted bool
	Status   int
	Reason   string
	Warning  string
}

// controllingFunction is the seam toward the controlling role of one group.
type controllingFunction interface {
	// AdmitOriginatingCall applies the group's admission policy to an
	// originating leg (TS 24.379 clauses 6.3.5/6.3.6 once conformant;
	// today the existing membership check).
	AdmitOriginatingCall(ctx context.Context, call originatingGroupCall) admissionVerdict

	// EstablishGroupLegs invites the group's other participants for an
	// admitted call. Asynchronous: legs progress independently of the
	// originating leg's response in this slice (the 6.3.3.2.3.2 ordering
	// fix is slice 3).
	EstablishGroupLegs(call originatingGroupCall)

	// ReleaseGroupLegs terminates the server-initiated legs of a group call
	// when the originating leg ends.
	ReleaseGroupLegs(groupURI, callID string)
}

// controllingFor resolves the controlling function for a group (decision D3).
// Every group homes locally today; a remote SIP binding keyed by group
// configuration replaces this lookup's answer, not its callers.
func (s *Server) controllingFor(groupURI string) controllingFunction {
	return localControlling{s: s}
}

// localControlling is the in-process controlling function, delegating to the
// pre-existing group-call code paths unchanged.
type localControlling struct {
	s *Server
}

func (c localControlling) AdmitOriginatingCall(ctx context.Context, call originatingGroupCall) admissionVerdict {
	return c.s.admitGroupInvite(ctx, call.InitiatorURI, call.GroupURI)
}

func (c localControlling) EstablishGroupLegs(call originatingGroupCall) {
	// Synchronous through the initial sends: TS 24.379 clause 10.1.1.4.2
	// step 14 g v invites the members before the originating leg's final
	// response, so the caller answers the originator only once every member
	// INVITE is on the wire. Each leg's response handling detaches inside
	// sendRXInvite; the store context is independent of the inbound handler.
	c.s.sendGroupCallNotifications(context.Background(), call.CallID, call.GroupURI, call.InitiatorURI, call.SDP)
}

func (c localControlling) ReleaseGroupLegs(groupURI, callID string) {
	go c.s.terminateRXLegs(context.Background(), groupURI, callID)
}
