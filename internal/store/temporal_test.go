package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func clockAt(ts string) func() time.Time {
	return func() time.Time {
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			panic(err)
		}
		return parsed
	}
}

func seedTemporalWorld(t *testing.T, st *Store) {
	t.Helper()
	for _, value := range [][2]string{
		{KindSubject, "alice"}, {KindResource, "doc"}, {KindOperation, "read"},
		{KindPermission, "p1"}, {KindRole, "r1"},
	} {
		if err := st.PutEntity(value[0], value[1], value[1]); err != nil {
			t.Fatalf("put %s: %v", value, err)
		}
	}
	if err := st.AddLink("permission_operations", "p1", "read"); err != nil {
		t.Fatalf("perm op: %v", err)
	}
}

func TestBindingIntervalsOpenCloseAndIdempotent(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return base }
	st.SetClock(clock)
	seedTemporalWorld(t, st)

	if err := st.BindSubjectRole("alice", "r1", "exact", "doc"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// Same identity while open is idempotent, not a duplicate interval.
	if err := st.BindSubjectRole("alice", "r1", "exact", "doc"); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("rebind err = %v, want ErrAlreadyOpen", err)
	}

	// Advancing the clock closes the old window at the new instant.
	base = base.Add(time.Hour)
	if err := st.UnbindSubjectRole("alice", "r1", "exact", "doc"); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	// Revoking again finds no open window.
	if err := st.UnbindSubjectRole("alice", "r1", "exact", "doc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reunbind err = %v, want ErrNotFound", err)
	}

	var count int
	if err := st.db.QueryRow(
		`SELECT COUNT(*) FROM subject_role_intervals WHERE subject_id = 'alice'`).
		Scan(&count); err != nil || count != 1 {
		t.Fatalf("intervals = %d err=%v, want 1", count, err)
	}
}

func TestFixedClockProducesDistinctOrderedWindows(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	st.SetClock(clockAt("2025-01-01T00:00:00Z"))
	seedTemporalWorld(t, st)

	if err := st.BindSubjectRole("alice", "r1", "exact", "doc"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := st.UnbindSubjectRole("alice", "r1", "exact", "doc"); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if err := st.BindSubjectRole("alice", "r1", "all", ""); err != nil {
		t.Fatalf("rebind: %v", err)
	}

	rows, err := st.db.Query(
		`SELECT valid_from, valid_to, seq FROM subject_role_intervals
		 WHERE subject_id = 'alice' ORDER BY valid_from`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	type window struct {
		from, to, seq int64
		hasTo         bool
	}
	var windows []window
	for rows.Next() {
		var w window
		var to *int64
		if err := rows.Scan(&w.from, &to, &w.seq); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if to != nil {
			w.to, w.hasTo = *to, true
		}
		windows = append(windows, w)
	}
	if len(windows) != 2 || windows[0].from >= windows[1].from {
		t.Fatalf("windows = %+v, want two strictly ordered windows", windows)
	}
	if !windows[0].hasTo || windows[0].to > windows[1].from {
		t.Fatalf("first window must close before the second opens: %+v", windows)
	}
	if windows[0].seq >= windows[1].seq {
		t.Fatalf("seq not ordered: %+v", windows)
	}
}

func TestUpdateScopeClosesWithUpdateReason(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	st.SetClock(clockAt("2025-01-01T00:00:00Z"))
	seedTemporalWorld(t, st)

	if err := st.BindSubjectRole("alice", "r1", "exact", "doc"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := st.UpdateSubjectRoleScope("alice", "r1", "exact", "doc", "all", ""); err != nil {
		t.Fatalf("update scope: %v", err)
	}

	rows, err := st.db.Query(
		`SELECT scope_kind, valid_to IS NULL, COALESCE(close_reason,'')
		 FROM subject_role_intervals WHERE subject_id = 'alice' ORDER BY valid_from`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	type row struct {
		kind   string
		open   bool
		reason string
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.kind, &r.open, &r.reason); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	if len(got) != 2 || got[0].open || got[0].reason != CloseUpdate || !got[1].open {
		t.Fatalf("rows = %+v, want closed-with-update then open", got)
	}
}
