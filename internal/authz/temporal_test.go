package authz

import (
	"testing"
	"time"
)

func nanos(ts string) int64 {
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic(err)
	}
	return parsed.UnixNano()
}

var input = Input{Subject: "alice", Resource: "doc", Operation: "read"}

func worldData() Data {
	return Data{
		PermissionOperations: []PermissionOperation{{Permission: "p1", Operation: "read"}},
		RolePermissionVersions: []RolePermissionVersion{{
			Role: "r1", Permission: "p1",
			From: nanos("2025-01-01T00:00:00Z"),
		}},
	}
}

func TestEvaluateAtReasons(t *testing.T) {
	cases := []struct {
		name string
		data Data
		at   string
		want string
	}{
		{
			name: "no binding at all",
			data: worldData(),
			at:   "2025-06-01T00:00:00Z",
			want: ReasonNoRoleBinding,
		},
		{
			name: "binding exists but no covering permission",
			data: func() Data {
				d := worldData()
				d.RolePermissionVersions = nil
				d.RoleVersions = []RoleVersion{{
					Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
					From: nanos("2025-01-01T00:00:00Z"),
				}}
				return d
			}(),
			at:   "2025-06-01T00:00:00Z",
			want: ReasonNoPermissionBinding,
		},
		{
			name: "covering permission but scope misses the resource",
			data: func() Data {
				d := worldData()
				d.RoleVersions = []RoleVersion{{
					Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "other"},
					From: nanos("2025-01-01T00:00:00Z"),
				}}
				return d
			}(),
			at:   "2025-06-01T00:00:00Z",
			want: ReasonOutOfScope,
		},
		{
			name: "structural match but before any window opens",
			data: func() Data {
				d := worldData()
				d.RoleVersions = []RoleVersion{{
					Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
					From: nanos("2025-06-01T00:00:00Z"),
				}}
				return d
			}(),
			at:   "2025-01-01T00:00:00Z",
			want: ReasonNotEffective,
		},
		{
			name: "granted inside the window",
			data: func() Data {
				d := worldData()
				d.RoleVersions = []RoleVersion{{
					Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
					From: nanos("2025-01-01T00:00:00Z"),
				}}
				return d
			}(),
			at:   "2025-06-01T00:00:00Z",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := EvaluateAt(input, tc.data, nanos(tc.at))
			if tc.want == "" {
				if !decision.Granted || decision.Match == nil {
					t.Fatalf("decision = %+v, want granted with a match", decision)
				}
				if decision.Match.Role != "r1" || decision.Match.Permission != "p1" {
					t.Fatalf("match = %+v", decision.Match)
				}
				return
			}
			if decision.Granted || decision.Reason != tc.want {
				t.Fatalf("decision = %+v, want reason %s", decision, tc.want)
			}
		})
	}
}

func TestEvaluateAtRevokedWindowIsNotEffective(t *testing.T) {
	d := worldData()
	d.RoleVersions = []RoleVersion{{
		Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
		From: nanos("2025-01-01T00:00:00Z"),
		To:   nanos("2025-02-01T00:00:00Z"), HasTo: true,
	}}
	if decision := EvaluateAt(input, d, nanos("2025-03-01T00:00:00Z")); decision.Granted ||
		decision.Reason != ReasonNotEffective {
		t.Fatalf("after close decision = %+v, want NOT_EFFECTIVE", decision)
	}
	if decision := EvaluateAt(input, d, nanos("2025-01-15T00:00:00Z")); !decision.Granted {
		t.Fatalf("inside window decision = %+v, want granted", decision)
	}
}

func TestTimelineGrantUpdateRevoke(t *testing.T) {
	d := worldData()
	from := nanos("2025-01-01T00:00:00Z")
	updateAt := nanos("2025-02-01T00:00:00Z")
	revokeAt := nanos("2025-03-01T00:00:00Z")
	d.RoleVersions = []RoleVersion{
		{
			Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
			From: from, To: updateAt, HasTo: true, CloseReason: CloseUpdate, Seq: 1,
		},
		{
			Role: "r1", Scope: Scope{Kind: ScopeAll},
			From: updateAt, To: revokeAt, HasTo: true, Seq: 2,
		},
	}
	// The final window is closed by a revoke; represent it by marking the open
	// interval with a revoke close at revokeAt via a third closed row pair is
	// unnecessary: close the second row with reason revoke.
	d.RoleVersions[1].CloseReason = CloseRevoke

	events := Timeline(input, d, HistoryRange{})
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3: %+v", len(events), events)
	}
	want := []struct {
		kind    string
		at      int64
		granted bool
		scope   Scope
	}{
		{EventGrant, from, true, Scope{Kind: ScopeExact, Value: "doc"}},
		{EventUpdate, updateAt, true, Scope{Kind: ScopeAll}},
		{EventRevoke, revokeAt, false, Scope{Kind: ScopeAll}},
	}
	for i, expected := range want {
		got := events[i]
		if got.Event != expected.kind || got.OccurredAt != expected.at ||
			got.Granted != expected.granted || got.Scope != expected.scope {
			t.Fatalf("event %d = %+v, want %+v", i, got, expected)
		}
	}
	if events[0].EffectiveTo == nil || *events[0].EffectiveTo != updateAt {
		t.Fatalf("grant effectiveTo = %v, want %d", events[0].EffectiveTo, updateAt)
	}
	if events[2].EffectiveTo == nil || *events[2].EffectiveTo != revokeAt {
		t.Fatalf("revoke effectiveTo = %v, want %d", events[2].EffectiveTo, revokeAt)
	}
}

func TestTimelineEmptyAndRange(t *testing.T) {
	d := worldData()
	if events := Timeline(input, d, HistoryRange{}); len(events) != 0 {
		t.Fatalf("no binding should yield no events, got %+v", events)
	}
	d.RoleVersions = []RoleVersion{{
		Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
		From: nanos("2025-01-01T00:00:00Z"), Seq: 1,
	}}
	ranged := Timeline(input, d, HistoryRange{
		HasFrom: true, From: nanos("2026-01-01T00:00:00Z"),
		HasTo: true, To: nanos("2026-02-01T00:00:00Z"),
	})
	if len(ranged) != 0 {
		t.Fatalf("range outside events should be empty, got %+v", ranged)
	}
}

func TestTimelineRolePermissionLayerRevokeAndRegrant(t *testing.T) {
	g1 := nanos("2025-01-01T00:00:00Z")
	r1 := nanos("2025-02-01T00:00:00Z")
	g2 := nanos("2025-03-01T00:00:00Z")
	d := Data{
		PermissionOperations: []PermissionOperation{{Permission: "p1", Operation: "read"}},
		RoleVersions: []RoleVersion{{
			Role: "r1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
			From: g1, Seq: 1,
		}},
		RolePermissionVersions: []RolePermissionVersion{
			{Role: "r1", Permission: "p1", From: g1, To: r1, HasTo: true, Seq: 2},
			{Role: "r1", Permission: "p1", From: g2, Seq: 3},
		},
	}
	events := Timeline(input, d, HistoryRange{})
	kinds := make([]string, 0, len(events))
	for _, event := range events {
		kinds = append(kinds, event.Event)
		if event.Scope != (Scope{Kind: ScopeExact, Value: "doc"}) {
			t.Fatalf("scope = %v, want binding scope doc/exact", event.Scope)
		}
	}
	joined := ""
	for _, k := range kinds {
		joined += k + ","
	}
	if joined != "GRANT,REVOKE,GRANT," {
		t.Fatalf("kinds = %s, want GRANT,REVOKE,GRANT", joined)
	}
}

func TestTimelineDirectGrant(t *testing.T) {
	g := nanos("2025-01-01T00:00:00Z")
	r := nanos("2025-02-01T00:00:00Z")
	d := Data{
		PermissionOperations: []PermissionOperation{{Permission: "p1", Operation: "read"}},
		GrantVersions: []GrantVersion{{
			Permission: "p1", Scope: Scope{Kind: ScopeExact, Value: "doc"},
			From: g, To: r, HasTo: true, CloseReason: CloseRevoke, Seq: 5,
		}},
	}
	events := Timeline(input, d, HistoryRange{})
	if len(events) != 2 {
		t.Fatalf("events = %d: %+v", len(events), events)
	}
	if events[0].Event != EventGrant || events[0].Role != "" {
		t.Fatalf("first = %+v", events[0])
	}
	if events[1].Event != EventRevoke || events[1].Role != "" {
		t.Fatalf("second = %+v", events[1])
	}
}
