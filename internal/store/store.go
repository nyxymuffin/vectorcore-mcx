package store

import (
	"context"
	"time"
)

type User struct {
	ID          string    `json:"id,omitempty"`
	IMPI        string    `json:"impi"`
	IMPU        string    `json:"impu"`
	MCPTTID     string    `json:"mcptt_id"`
	DisplayName string    `json:"display_name"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type Group struct {
	ID          string    `json:"id,omitempty"`
	URI         string    `json:"uri"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type GroupMembership struct {
	ID        string    `json:"id,omitempty"`
	UserID    string    `json:"user_id"`
	GroupID   string    `json:"group_id"`
	Role      string    `json:"role"`
	Priority  int       `json:"priority"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type GroupAffiliation struct {
	ID                string    `json:"id,omitempty"`
	UserID            string    `json:"user_id"`
	GroupID           string    `json:"group_id"`
	State             string    `json:"state"`
	Source            string    `json:"source,omitempty"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
	LastPublishCallID string    `json:"last_publish_call_id,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

type CMSDocument struct {
	ID          string    `json:"id,omitempty"`
	Name        string    `json:"name"`
	AUID        string    `json:"auid"`
	Path        string    `json:"path"`
	ContentType string    `json:"content_type"`
	Body        string    `json:"body"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type PublishedState struct {
	ID        string    `json:"id,omitempty"`
	UserURI   string    `json:"user_uri"`
	Event     string    `json:"event"`
	Body      string    `json:"body"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type Subscription struct {
	ID            string    `json:"id,omitempty"`
	CallID        string    `json:"call_id"`
	Event         string    `json:"event"`
	SubscriberURI string    `json:"subscriber_uri"`
	TargetURI     string    `json:"target_uri"`
	Selectors     []string  `json:"selectors,omitempty"`
	LocalTag      string    `json:"local_tag"`
	RemoteTag     string    `json:"remote_tag"`
	RouteSet      string    `json:"route_set"`
	RemoteTarget  string    `json:"remote_target"`
	Transport     string    `json:"transport"`
	SourceAddr    string    `json:"source_addr"`
	TopVia        string    `json:"top_via"`
	State         string    `json:"state"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type Dialog struct {
	ID              string    `json:"id,omitempty"`
	CallID          string    `json:"call_id"`
	LocalTag        string    `json:"local_tag"`
	RemoteTag       string    `json:"remote_tag"`
	FromURI         string    `json:"from_uri,omitempty"`
	ToURI           string    `json:"to_uri,omitempty"`
	RequestURI      string    `json:"request_uri,omitempty"`
	IMPU            string    `json:"impu,omitempty"`
	MCPTTID         string    `json:"mcptt_id,omitempty"`
	Method          string    `json:"method"`
	State           string    `json:"state"`
	RouteSet        string    `json:"route_set"`
	RemoteTarget    string    `json:"remote_target"`
	RecordRouteUsed bool      `json:"record_route_used"`
	LocalCSeq       uint32    `json:"local_cseq,omitempty"`
	RemoteCSeq      uint32    `json:"remote_cseq,omitempty"`
	LastMethod      string    `json:"last_method,omitempty"`
	LastStatus      int       `json:"last_status,omitempty"`
	Transport       string    `json:"transport"`
	SourceAddr      string    `json:"source_addr"`
	TopVia          string    `json:"top_via"`
	CreatedAt       time.Time `json:"created_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}

type Registration struct {
	ID                 string    `json:"id,omitempty"`
	PublicIdentity     string    `json:"public_identity"`
	IMSI               string    `json:"imsi,omitempty"`
	MSISDN             string    `json:"msisdn,omitempty"`
	MCPTTID            string    `json:"mcptt_id,omitempty"`
	ContactURI         string    `json:"contact_uri,omitempty"`
	ContactRaw         string    `json:"contact_raw,omitempty"`
	SourceIP           string    `json:"source_ip,omitempty"`
	SourcePort         int       `json:"source_port,omitempty"`
	Transport          string    `json:"transport,omitempty"`
	CallID             string    `json:"call_id,omitempty"`
	CSeq               string    `json:"cseq,omitempty"`
	Registered         bool      `json:"registered"`
	State              string    `json:"state"`
	ExpiresAt          time.Time `json:"expires_at,omitempty"`
	ExpiresSeconds     int       `json:"expires_seconds,omitempty"`
	LastRegisteredAt   time.Time `json:"last_registered_at,omitempty"`
	LastUnregisteredAt time.Time `json:"last_unregistered_at,omitempty"`
	LastSeenAt         time.Time `json:"last_seen_at,omitempty"`
	UserAgent          string    `json:"user_agent,omitempty"`
	FeatureTags        []string  `json:"feature_tags,omitempty"`
	ICSIRefs           []string  `json:"icsi_refs,omitempty"`
	SCSCFIdentity      string    `json:"scscf_identity,omitempty"`
	RegistrationSource string    `json:"registration_source"`
}

type RegistrationSummary struct {
	RegisteredClients    int        `json:"registered_clients"`
	RegisteredUsers      int        `json:"registered_users"`
	ExpiredRegistrations int        `json:"expired_registrations"`
	UnregisteredRecent   int        `json:"unregistered_recent"`
	LastEventAt          *time.Time `json:"last_event_at,omitempty"`
}

type MCPTTCall struct {
	ID                   string    `json:"id,omitempty"`
	CallID               string    `json:"call_id"`
	State                string    `json:"state"`
	InitiatorURI         string    `json:"initiator_uri,omitempty"`
	TargetURI            string    `json:"target_uri,omitempty"`
	GroupURI             string    `json:"group_uri,omitempty"`
	MCPTTID              string    `json:"mcptt_id,omitempty"`
	RemoteTarget         string    `json:"remote_target,omitempty"`
	RouteSet             string    `json:"route_set,omitempty"`
	LocalTag             string    `json:"local_tag,omitempty"`
	RemoteTag            string    `json:"remote_tag,omitempty"`
	Transport            string    `json:"transport,omitempty"`
	SourceAddr           string    `json:"source_addr,omitempty"`
	AudioIP              string    `json:"audio_ip,omitempty"`
	AudioPort            int       `json:"audio_port,omitempty"`
	AudioProto           string    `json:"audio_proto,omitempty"`
	AudioPayloads        []string  `json:"audio_payloads,omitempty"`
	FloorControlIP       string    `json:"floor_control_ip,omitempty"`
	FloorControlPort     int       `json:"floor_control_port,omitempty"`
	FloorControlProto    string    `json:"floor_control_proto,omitempty"`
	FloorControlPayloads []string  `json:"floor_control_payloads,omitempty"`
	MediaAttributes      []string  `json:"media_attributes,omitempty"`
	FloorControlAttrs    []string  `json:"floor_control_attrs,omitempty"`
	LocalAudioPort       int       `json:"local_audio_port,omitempty"`
	LocalRTCPPort        int       `json:"local_rtcp_port,omitempty"`
	LocalFloorPort       int       `json:"local_floor_port,omitempty"`
	RTPPackets           int64     `json:"rtp_packets,omitempty"`
	RTPBytes             int64     `json:"rtp_bytes,omitempty"`
	RTPRejectedPackets   int64     `json:"rtp_rejected_packets,omitempty"`
	RTPRejectedBytes     int64     `json:"rtp_rejected_bytes,omitempty"`
	RTPPayloadType       int       `json:"rtp_payload_type,omitempty"`
	RTPSSRC              uint32    `json:"rtp_ssrc,omitempty"`
	RTPFirstSequence     uint16    `json:"rtp_first_sequence,omitempty"`
	RTPLastSequence      uint16    `json:"rtp_last_sequence,omitempty"`
	RTPLastTimestamp     uint32    `json:"rtp_last_timestamp,omitempty"`
	RTPSequenceCycles    int64     `json:"rtp_sequence_cycles,omitempty"`
	RTPExpectedPackets   int64     `json:"rtp_expected_packets,omitempty"`
	RTPLostPackets       int64     `json:"rtp_lost_packets,omitempty"`
	RTPJitter            float64   `json:"rtp_jitter,omitempty"`
	RTCPPackets          int64     `json:"rtcp_packets,omitempty"`
	RTCPBytes            int64     `json:"rtcp_bytes,omitempty"`
	FloorPackets         int64     `json:"floor_packets,omitempty"`
	FloorBytes           int64     `json:"floor_bytes,omitempty"`
	FloorState           string    `json:"floor_state,omitempty"`
	FloorLastEvent       string    `json:"floor_last_event,omitempty"`
	FloorLastSubtype     int       `json:"floor_last_subtype,omitempty"`
	FloorSSRC            uint32    `json:"floor_ssrc,omitempty"`
	FloorHolder          string    `json:"floor_holder,omitempty"`
	FloorGrantedAt       time.Time `json:"floor_granted_at,omitempty"`
	FloorReleasedAt      time.Time `json:"floor_released_at,omitempty"`
	FloorUpdatedAt       time.Time `json:"floor_updated_at,omitempty"`
	LastRTPAt            time.Time `json:"last_rtp_at,omitempty"`
	LastRTCPAt           time.Time `json:"last_rtcp_at,omitempty"`
	LastFloorAt          time.Time `json:"last_floor_at,omitempty"`
	SDPOffer             string    `json:"sdp_offer,omitempty"`
	SDPAnswer            string    `json:"sdp_answer,omitempty"`
	CreatedAt            time.Time `json:"created_at,omitempty"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
	AnsweredAt           time.Time `json:"answered_at,omitempty"`
	EstablishedAt        time.Time `json:"established_at,omitempty"`
	TerminatedAt         time.Time `json:"terminated_at,omitempty"`
}

type CallSummary struct {
	ActiveCalls          int        `json:"active_calls"`
	EarlyCalls           int        `json:"early_calls"`
	EstablishedCalls     int        `json:"established_calls"`
	TerminatingCalls     int        `json:"terminating_calls"`
	TerminatedCallsTotal int        `json:"terminated_calls_total"`
	RecentlyEnded        int        `json:"recently_ended"`
	ActiveRTPCalls       int        `json:"active_rtp_calls"`
	FloorGrantedCalls    int        `json:"floor_granted_calls"`
	TotalRTPPackets      int64      `json:"total_rtp_packets"`
	TotalRTPBytes        int64      `json:"total_rtp_bytes"`
	TotalRTPLostPackets  int64      `json:"total_rtp_lost_packets"`
	MaxRTPJitter         float64    `json:"max_rtp_jitter"`
	LastBYEAt            *time.Time `json:"last_bye_at,omitempty"`
	LastMediaAt          *time.Time `json:"last_media_at,omitempty"`
	LastEventAt          *time.Time `json:"last_event_at,omitempty"`
	SIPDialogs           int        `json:"sip_dialogs"`
}

type Store interface {
	Close() error

	ListUsers(context.Context) ([]User, error)
	GetUser(context.Context, string) (*User, error)
	CreateUser(context.Context, User) (User, error)
	UpdateUser(context.Context, string, User) (*User, error)
	DeleteUser(context.Context, string) error

	ListGroups(context.Context) ([]Group, error)
	GetGroup(context.Context, string) (*Group, error)
	CreateGroup(context.Context, Group) (Group, error)
	UpdateGroup(context.Context, string, Group) (*Group, error)
	DeleteGroup(context.Context, string) error

	ListGroupMemberships(context.Context) ([]GroupMembership, error)
	GetGroupMembership(context.Context, string) (*GroupMembership, error)
	CreateGroupMembership(context.Context, GroupMembership) (GroupMembership, error)
	UpdateGroupMembership(context.Context, string, GroupMembership) (*GroupMembership, error)
	DeleteGroupMembership(context.Context, string) error
	IsGroupMember(context.Context, string, string) (bool, error)

	ListGroupAffiliations(context.Context) ([]GroupAffiliation, error)
	GetGroupAffiliation(context.Context, string) (*GroupAffiliation, error)
	CreateGroupAffiliation(context.Context, GroupAffiliation) (GroupAffiliation, error)
	UpdateGroupAffiliation(context.Context, string, GroupAffiliation) (*GroupAffiliation, error)
	DeleteGroupAffiliation(context.Context, string) error
	IsGroupAffiliated(context.Context, string, string) (bool, error)

	ListCMSDocuments(context.Context) ([]CMSDocument, error)
	GetCMSDocument(context.Context, string) (*CMSDocument, error)
	GetCMSDocumentByPath(context.Context, string) (*CMSDocument, error)
	CreateCMSDocument(context.Context, CMSDocument) (CMSDocument, error)
	UpdateCMSDocument(context.Context, string, CMSDocument) (*CMSDocument, error)
	DeleteCMSDocument(context.Context, string) error

	UpsertPublishedState(context.Context, PublishedState) (PublishedState, error)
	CreateSubscription(context.Context, Subscription) (Subscription, error)
	CreateDialog(context.Context, Dialog) (Dialog, error)
	UpdateDialogState(context.Context, string, string) error
	FindDialog(context.Context, string, string, string) (*Dialog, error)
	ListDialogs(context.Context) ([]Dialog, error)

	UpsertRegistration(context.Context, Registration) (Registration, error)
	ListRegistrations(context.Context) ([]Registration, error)
	GetRegistration(context.Context, string) (*Registration, error)
	RegistrationSummary(context.Context) (RegistrationSummary, error)
	ExpireRegistrations(context.Context, time.Time) (int, error)

	SetUEContactIP(ctx context.Context, ueIP, mcpttID string) error
	GetMCPTTIDByUEIP(ctx context.Context, ueIP string) (string, error)

	UpsertCall(context.Context, MCPTTCall) (MCPTTCall, error)
	ListCalls(context.Context) ([]MCPTTCall, error)
	ListCallsByGroup(context.Context, string) ([]MCPTTCall, error)
	GetCall(context.Context, string) (*MCPTTCall, error)
	UpdateCallState(context.Context, string, string) error
	IncrementCallMedia(context.Context, string, string, int) error
	UpdateCallRTPStats(context.Context, string, RTPStatsUpdate) error
	UpdateCallFloorState(context.Context, string, FloorStateUpdate) error
	CallSummary(context.Context) (CallSummary, error)
}

type RTPStatsUpdate struct {
	PayloadType     int
	SSRC            uint32
	FirstSequence   uint16
	LastSequence    uint16
	LastTimestamp   uint32
	SequenceCycles  int64
	ExpectedPackets int64
	LostPackets     int64
	Jitter          float64
}

type FloorStateUpdate struct {
	State       string
	Event       string
	Subtype     int
	SSRC        uint32
	Holder      string
	ClearHolder bool
	At          time.Time
}
