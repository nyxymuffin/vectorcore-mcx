package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

func dbErr(err error) error {
	if err == nil {
		return nil
	}
	slog.Error("database error", "err", err)
	return huma.Error500InternalServerError(err.Error(), err)
}

func notFound(msg string) error { return huma.Error404NotFound(msg, nil) }

type statusBody struct {
	Version       string                    `json:"version"`
	Uptime        string                    `json:"uptime"`
	UptimeSec     float64                   `json:"uptime_sec"`
	StartedAt     time.Time                 `json:"started_at"`
	IMSRealm      string                    `json:"ims_realm"`
	SIPIdentity   string                    `json:"sip_identity"`
	ServerName    string                    `json:"server_name"`
	UserCount     int                       `json:"user_count"`
	GroupCount    int                       `json:"group_count"`
	Memberships   int                       `json:"memberships"`
	Affiliations  int                       `json:"affiliations"`
	Registrations store.RegistrationSummary `json:"registrations"`
	Calls         store.CallSummary         `json:"calls"`
}

func registerStatus(api huma.API, s *Server) {
	huma.Register(api, huma.Operation{
		OperationID: "get-status",
		Method:      http.MethodGet,
		Path:        "/api/v1/status",
		Summary:     "Get system status",
		Tags:        []string{"OAM"},
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body statusBody }, error) {
		users, err := s.st.ListUsers(ctx)
		if err != nil {
			return nil, dbErr(err)
		}
		groups, err := s.st.ListGroups(ctx)
		if err != nil {
			return nil, dbErr(err)
		}
		memberships, err := s.st.ListGroupMemberships(ctx)
		if err != nil {
			return nil, dbErr(err)
		}
		aff, err := s.st.ListGroupAffiliations(ctx)
		if err != nil {
			return nil, dbErr(err)
		}
		if _, err := s.st.ExpireRegistrations(ctx, time.Now().UTC()); err != nil {
			return nil, dbErr(err)
		}
		regSummary, err := s.st.RegistrationSummary(ctx)
		if err != nil {
			return nil, dbErr(err)
		}
		callSummary, err := s.st.CallSummary(ctx)
		if err != nil {
			return nil, dbErr(err)
		}
		up := time.Since(s.startAt)
		return &struct{ Body statusBody }{Body: statusBody{
			Version:       s.version,
			Uptime:        up.Round(time.Second).String(),
			UptimeSec:     up.Seconds(),
			StartedAt:     s.startAt,
			IMSRealm:      s.cfg.IMS.Realm,
			SIPIdentity:   s.cfg.MCX.SIPIdentity,
			ServerName:    s.cfg.MCX.ServerName,
			UserCount:     len(users),
			GroupCount:    len(groups),
			Memberships:   len(memberships),
			Affiliations:  len(aff),
			Registrations: regSummary,
			Calls:         callSummary,
		}}, nil
	})
}

func registerUsers(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-users", Method: http.MethodGet, Path: "/api/v1/users", Summary: "List MCX users", Tags: []string{"Users"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.User }, error) {
			v, err := st.ListUsers(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.User{}
			}
			return &struct{ Body []store.User }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-user", Method: http.MethodGet, Path: "/api/v1/users/{id}", Summary: "Get MCX user", Tags: []string{"Users"}},
		func(ctx context.Context, input *struct {
			ID string `path:"id"`
		}) (*struct{ Body store.User }, error) {
			v, err := st.GetUser(ctx, input.ID)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("user not found")
			}
			return &struct{ Body store.User }{*v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-user", Method: http.MethodPost, Path: "/api/v1/users", Summary: "Create MCX user", Tags: []string{"Users"}, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, input *struct{ Body store.User }) (*struct{ Body store.User }, error) {
			v, err := st.CreateUser(ctx, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			return &struct{ Body store.User }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-user", Method: http.MethodPut, Path: "/api/v1/users/{id}", Summary: "Update MCX user", Tags: []string{"Users"}},
		func(ctx context.Context, input *struct {
			ID   string `path:"id"`
			Body store.User
		}) (*struct{ Body store.User }, error) {
			v, err := st.UpdateUser(ctx, input.ID, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("user not found")
			}
			return &struct{ Body store.User }{*v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-user", Method: http.MethodDelete, Path: "/api/v1/users/{id}", Summary: "Delete MCX user", Tags: []string{"Users"}, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, input *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			return nil, dbErr(st.DeleteUser(ctx, input.ID))
		})
}

func registerGroups(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-groups", Method: http.MethodGet, Path: "/api/v1/groups", Summary: "List GMS groups", Tags: []string{"GMS"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.Group }, error) {
			v, err := st.ListGroups(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.Group{}
			}
			return &struct{ Body []store.Group }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-group", Method: http.MethodPost, Path: "/api/v1/groups", Summary: "Create GMS group", Tags: []string{"GMS"}, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, input *struct{ Body store.Group }) (*struct{ Body store.Group }, error) {
			v, err := st.CreateGroup(ctx, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			return &struct{ Body store.Group }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-group", Method: http.MethodPut, Path: "/api/v1/groups/{id}", Summary: "Update GMS group", Tags: []string{"GMS"}},
		func(ctx context.Context, input *struct {
			ID   string `path:"id"`
			Body store.Group
		}) (*struct{ Body store.Group }, error) {
			v, err := st.UpdateGroup(ctx, input.ID, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("group not found")
			}
			return &struct{ Body store.Group }{*v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-group", Method: http.MethodDelete, Path: "/api/v1/groups/{id}", Summary: "Delete GMS group", Tags: []string{"GMS"}, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, input *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			return nil, dbErr(st.DeleteGroup(ctx, input.ID))
		})
}

func registerMemberships(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-memberships", Method: http.MethodGet, Path: "/api/v1/memberships", Summary: "List static group memberships", Tags: []string{"GMS"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.GroupMembership }, error) {
			v, err := st.ListGroupMemberships(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.GroupMembership{}
			}
			return &struct{ Body []store.GroupMembership }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-membership", Method: http.MethodPost, Path: "/api/v1/memberships", Summary: "Create static group membership", Tags: []string{"GMS"}, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, input *struct{ Body store.GroupMembership }) (*struct{ Body store.GroupMembership }, error) {
			v, err := st.CreateGroupMembership(ctx, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			return &struct{ Body store.GroupMembership }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-membership", Method: http.MethodPut, Path: "/api/v1/memberships/{id}", Summary: "Update static group membership", Tags: []string{"GMS"}},
		func(ctx context.Context, input *struct {
			ID   string `path:"id"`
			Body store.GroupMembership
		}) (*struct{ Body store.GroupMembership }, error) {
			v, err := st.UpdateGroupMembership(ctx, input.ID, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("membership not found")
			}
			return &struct{ Body store.GroupMembership }{*v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-membership", Method: http.MethodDelete, Path: "/api/v1/memberships/{id}", Summary: "Delete static group membership", Tags: []string{"GMS"}, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, input *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			return nil, dbErr(st.DeleteGroupMembership(ctx, input.ID))
		})
}

func registerGroupAffiliations(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-group-affiliations", Method: http.MethodGet, Path: "/api/v1/group-affiliations", Summary: "List runtime MCPTT group affiliations", Tags: []string{"GMS"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.GroupAffiliation }, error) {
			v, err := st.ListGroupAffiliations(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.GroupAffiliation{}
			}
			return &struct{ Body []store.GroupAffiliation }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-group-affiliation", Method: http.MethodPost, Path: "/api/v1/group-affiliations", Summary: "Create runtime MCPTT group affiliation", Tags: []string{"GMS"}, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, input *struct{ Body store.GroupAffiliation }) (*struct{ Body store.GroupAffiliation }, error) {
			v, err := st.CreateGroupAffiliation(ctx, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			slog.Info("MCPTT affiliation changed", "operation", "api_create", "user_id", v.UserID, "group_id", v.GroupID, "previous_state", "", "state", v.State, "source", v.Source, "affiliation_id", v.ID)
			return &struct{ Body store.GroupAffiliation }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-group-affiliation", Method: http.MethodPut, Path: "/api/v1/group-affiliations/{id}", Summary: "Update runtime MCPTT group affiliation", Tags: []string{"GMS"}},
		func(ctx context.Context, input *struct {
			ID   string `path:"id"`
			Body store.GroupAffiliation
		}) (*struct{ Body store.GroupAffiliation }, error) {
			previous, err := st.GetGroupAffiliation(ctx, input.ID)
			if err != nil {
				return nil, dbErr(err)
			}
			v, err := st.UpdateGroupAffiliation(ctx, input.ID, input.Body)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("group affiliation not found")
			}
			previousState := ""
			if previous != nil {
				previousState = previous.State
			}
			slog.Info("MCPTT affiliation changed", "operation", "api_update", "user_id", v.UserID, "group_id", v.GroupID, "previous_state", previousState, "state", v.State, "source", v.Source, "affiliation_id", v.ID)
			return &struct{ Body store.GroupAffiliation }{*v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-group-affiliation", Method: http.MethodDelete, Path: "/api/v1/group-affiliations/{id}", Summary: "Delete runtime MCPTT group affiliation", Tags: []string{"GMS"}, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, input *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			previous, err := st.GetGroupAffiliation(ctx, input.ID)
			if err != nil {
				return nil, dbErr(err)
			}
			if err := st.DeleteGroupAffiliation(ctx, input.ID); err != nil {
				return nil, dbErr(err)
			}
			if previous != nil {
				slog.Info("MCPTT affiliation changed", "operation", "api_delete", "user_id", previous.UserID, "group_id", previous.GroupID, "previous_state", previous.State, "state", "", "source", previous.Source, "affiliation_id", previous.ID)
			}
			return nil, nil
		})
}

func registerRegistrations(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-registrations", Method: http.MethodGet, Path: "/api/v1/registrations", Summary: "List MCPTT registrations", Tags: []string{"Registrations"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.Registration }, error) {
			if _, err := st.ExpireRegistrations(ctx, time.Now().UTC()); err != nil {
				return nil, dbErr(err)
			}
			v, err := st.ListRegistrations(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.Registration{}
			}
			return &struct{ Body []store.Registration }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "registration-summary", Method: http.MethodGet, Path: "/api/v1/registrations/summary", Summary: "Get MCPTT registration summary", Tags: []string{"Registrations"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body store.RegistrationSummary }, error) {
			if _, err := st.ExpireRegistrations(ctx, time.Now().UTC()); err != nil {
				return nil, dbErr(err)
			}
			v, err := st.RegistrationSummary(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			return &struct{ Body store.RegistrationSummary }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-registration", Method: http.MethodGet, Path: "/api/v1/registrations/{public_identity}", Summary: "Get MCPTT registration", Tags: []string{"Registrations"}},
		func(ctx context.Context, input *struct {
			PublicIdentity string `path:"public_identity"`
		}) (*struct{ Body store.Registration }, error) {
			if _, err := st.ExpireRegistrations(ctx, time.Now().UTC()); err != nil {
				return nil, dbErr(err)
			}
			v, err := st.GetRegistration(ctx, input.PublicIdentity)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("registration not found")
			}
			return &struct{ Body store.Registration }{*v}, nil
		})
}

func registerCalls(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-calls", Method: http.MethodGet, Path: "/api/v1/calls", Summary: "List MCPTT calls", Tags: []string{"Calls"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.MCPTTCall }, error) {
			v, err := st.ListCalls(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.MCPTTCall{}
			}
			return &struct{ Body []store.MCPTTCall }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "call-summary", Method: http.MethodGet, Path: "/api/v1/calls/summary", Summary: "Get MCPTT call summary", Tags: []string{"Calls"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body store.CallSummary }, error) {
			v, err := st.CallSummary(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			return &struct{ Body store.CallSummary }{v}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-call", Method: http.MethodGet, Path: "/api/v1/calls/{call_id}", Summary: "Get MCPTT call", Tags: []string{"Calls"}},
		func(ctx context.Context, input *struct {
			CallID string `path:"call_id"`
		}) (*struct{ Body store.MCPTTCall }, error) {
			v, err := st.GetCall(ctx, input.CallID)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				return nil, notFound("call not found")
			}
			return &struct{ Body store.MCPTTCall }{*v}, nil
		})
}

func registerDialogs(api huma.API, st store.Store) {
	huma.Register(api, huma.Operation{OperationID: "list-dialogs", Method: http.MethodGet, Path: "/api/v1/dialogs", Summary: "List SIP dialogs", Tags: []string{"Calls"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []store.Dialog }, error) {
			v, err := st.ListDialogs(ctx)
			if err != nil {
				return nil, dbErr(err)
			}
			if v == nil {
				v = []store.Dialog{}
			}
			return &struct{ Body []store.Dialog }{v}, nil
		})
}
