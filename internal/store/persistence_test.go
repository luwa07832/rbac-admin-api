package store

import (
	"path/filepath"
	"testing"
)

func TestIntervalsSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.EnsureCatalog(CatalogSubject, "user-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureCatalog(CatalogRole, "viewer"); err != nil {
		t.Fatal(err)
	}
	if err := st.GrantBinding("user-1", "viewer", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	versions, err := reopened.ListBindingVersions("user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(versions) != 1 || versions[0].RoleID != "viewer" || versions[0].EffectiveTo != "" {
		t.Fatalf("versions = %+v", versions)
	}
}
