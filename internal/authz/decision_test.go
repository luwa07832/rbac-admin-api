package authz

import (
	"github.com/luwa07832/rbac-admin-api/internal/store"
	"path/filepath"
	"testing"
)

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewService(st), st
}

func seedService(t *testing.T, s *Service) {
	t.Helper()
	must(t, s.Register(RegisterInput{Kind: store.CatalogSubject, ID: "user-1"}))
	must(t, s.Register(RegisterInput{Kind: store.CatalogResource, ID: "tenant-a/doc-1"}))
	must(t, s.Register(RegisterInput{Kind: store.CatalogOperation, ID: "read"}))
	must(t, s.Register(RegisterInput{Kind: store.CatalogRole, ID: "viewer"}))
	must(t, s.Register(RegisterInput{Kind: store.CatalogPermission, ID: "doc-read"}))
	must(t, s.SetPermissionOperations(SetPermissionOperationsInput{PermissionID: "doc-read", Operations: []string{"read"}}))
}

func must(t *testing.T, fail *Failure) {
	t.Helper()
	if fail != nil {
		t.Fatalf("unexpected failure: %v", fail)
	}
}

func writeAt(s *Service, when string, fn func(string, string) *Failure) *Failure {
	return fn(when, when)
}

func TestDecideReasonsAtTimes(t *testing.T) {
	s, _ := newService(t)
	seedService(t, s)
	decide := func(when string) *Decision {
		d, fail := s.Decide(DecisionInput{Subject: "user-1", Resource: "tenant-a/doc-1", Operation: "read", EffectiveAt: when})
		if fail != nil {
			t.Fatalf("decide: %v", fail)
		}
		return d
	}

	if decide("2026-02-01T00:00:00Z").Reason != ReasonNoRoleBinding {
		t.Fatal("expected NO_ROLE_BINDING")
	}

	must(t, writeAt(s, "2026-01-01T00:00:00Z", func(occurred, from string) *Failure {
		return s.GrantBinding(LayerWrite{Subject: "user-1", Role: "viewer", OccurredAt: occurred, EffectiveFrom: from})
	}))
	if decide("2026-02-01T00:00:00Z").Reason != ReasonNoPermissionBinding {
		t.Fatal("expected NO_PERMISSION_BINDING")
	}

	must(t, writeAt(s, "2026-01-01T00:00:00Z", func(occurred, from string) *Failure {
		return s.GrantRolePermission(LayerWrite{Role: "viewer", Permission: "doc-read", OccurredAt: occurred, EffectiveFrom: from})
	}))
	if decide("2026-02-01T00:00:00Z").Reason != ReasonOutOfScope {
		t.Fatal("expected OUT_OF_SCOPE")
	}

	must(t, writeAt(s, "2026-03-01T00:00:00Z", func(occurred, from string) *Failure {
		return s.GrantScope(LayerWrite{Subject: "user-1", Role: "viewer", Scope: "tenant-a/*", OccurredAt: occurred, EffectiveFrom: from})
	}))
	if d := decide("2026-02-01T00:00:00Z"); d.Reason != ReasonNotEffective {
		t.Fatalf("future scope expected NOT_EFFECTIVE, got %s", d.Reason)
	}
	d := decide("2026-04-01T00:00:00Z")
	if !d.Granted || d.Match.Role != "viewer" || d.Match.Permission != "doc-read" || d.Match.Scope != "tenant-a/*" {
		t.Fatalf("granted decision = %+v", d)
	}

	must(t, s.RevokeScope(LayerWrite{
		Subject: "user-1", Role: "viewer", Scope: "tenant-a/*",
		OccurredAt: "2026-06-01T00:00:00Z", EffectiveFrom: "2026-06-01T00:00:00Z",
	}))
	if d := decide("2026-07-01T00:00:00Z"); d.Reason != ReasonNotEffective {
		t.Fatalf("revoked scope expected NOT_EFFECTIVE, got %s", d.Reason)
	}
}

func TestDecideUnknownTripleOrdering(t *testing.T) {
	s, _ := newService(t)
	seedService(t, s)

	d, fail := s.Decide(DecisionInput{Subject: "ghost", Resource: "tenant-a/doc-1", Operation: "read"})
	if d != nil || fail == nil || fail.Type != TypeNotFound || fail.Field != "subject" {
		t.Fatalf("subject = %+v %+v", d, fail)
	}
	must(t, s.Register(RegisterInput{Kind: store.CatalogSubject, ID: "ghost"}))
	_, fail = s.Decide(DecisionInput{Subject: "ghost", Resource: "missing/x", Operation: "read"})
	if fail == nil || fail.Type != TypeNotFound || fail.Field != "resource" {
		t.Fatalf("resource = %+v", fail)
	}
	_, fail = s.Decide(DecisionInput{Subject: "user-1", Resource: "tenant-a/doc-1", Operation: "destroy"})
	if fail == nil || fail.Type != TypeNotFound || fail.Field != "operation" {
		t.Fatalf("operation = %+v", fail)
	}
	_, fail = s.Decide(DecisionInput{Subject: "user-1", Resource: "tenant-a/doc-1", Operation: "read", EffectiveAt: "nope"})
	if fail == nil || fail.Type != TypeInvalidTime {
		t.Fatalf("time = %+v", fail)
	}
}

func TestHistoryEmptyAndRange(t *testing.T) {
	s, _ := newService(t)
	seedService(t, s)

	events, fail := s.History(HistoryInput{Subject: "user-1", Resource: "tenant-a/doc-1", Operation: "read"})
	if fail != nil || events == nil || len(events) != 0 {
		t.Fatalf("empty history = %+v %+v", events, fail)
	}
	_, fail = s.History(HistoryInput{
		Subject: "user-1", Resource: "tenant-a/doc-1", Operation: "read",
		From: "2026-09-01T00:00:00Z", To: "2026-01-01T00:00:00Z",
	})
	if fail == nil || fail.Type != TypeInvalidRange {
		t.Fatalf("range = %+v", fail)
	}
}

func TestOffsetTimestampsNormalizeToUTC(t *testing.T) {
	s, _ := newService(t)
	seedService(t, s)
	must(t, s.GrantBinding(LayerWrite{Subject: "user-1", Role: "viewer", EffectiveFrom: "2026-01-01T00:00:00Z"}))
	must(t, s.GrantRolePermission(LayerWrite{Role: "viewer", Permission: "doc-read", EffectiveFrom: "2026-01-01T00:00:00Z"}))
	must(t, s.GrantScope(LayerWrite{Subject: "user-1", Role: "viewer", Scope: "tenant-a/*", EffectiveFrom: "2026-01-01T00:00:00Z"}))

	// 2026-02-01T08:00:00+08:00 == 2026-02-01T00:00:00Z; the half-open
	// interval contains it (boundary equality is active).
	d, fail := s.Decide(DecisionInput{
		Subject: "user-1", Resource: "tenant-a/doc-1", Operation: "read",
		EffectiveAt: "2026-02-01T08:00:00+08:00",
	})
	if fail != nil {
		t.Fatalf("decide: %v", fail)
	}
	if !d.Granted {
		t.Fatalf("offset decision = %+v", d)
	}
}
