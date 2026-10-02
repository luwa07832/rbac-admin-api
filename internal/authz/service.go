package authz

import (
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// Service runs the time-aware authorization model over one store.
type Service struct {
	store *store.Store
}

// NewService wraps a store.
func NewService(st *store.Store) *Service { return &Service{store: st} }

// timings carries the canonical UTC texts of one write event.
type timings struct {
	occurredAt    string
	effectiveFrom string
}

// bindingRow is a flattened subject/role interval version.
type bindingRow struct {
	seq           int64
	roleID        string
	event         string
	occurredAt    string
	effectiveFrom string
	effectiveTo   string
	id            int64
}

// rolePermRow is a flattened role/permission interval version.
type rolePermRow struct {
	seq           int64
	roleID        string
	permissionID  string
	event         string
	occurredAt    string
	effectiveFrom string
	effectiveTo   string
	id            int64
}

// scopeRow is a flattened scoped authorization interval version. Exactly one
// of roleID and permissionID is set.
type scopeRow struct {
	seq           int64
	roleID        string
	permissionID  string
	scope         scopeRef
	event         string
	occurredAt    string
	effectiveFrom string
	effectiveTo   string
	id            int64
}

// snapshot is the complete read model needed for one decision or history
// query. Interval semantics are evaluated in Go in one place.
type snapshot struct {
	bindings []bindingRow
	rolePerm []rolePermRow
	scopes   []scopeRow

	// roleModel holds the current inheritance graph and the static operation
	// coverage of permissions; neither carries history intervals.
	roleModel
}

// roleModel is the history-free read model shared by every query: the
// current role inheritance graph in stored order and the operations
// statically covered by each permission.
type roleModel struct {
	roleParents    map[string][]string
	permOperations map[string]map[string]bool
}

func (s *Service) loadSnapshot(subject string) (*snapshot, error) {
	rolePermRows, err := s.loadRolePermissionRows()
	if err != nil {
		return nil, err
	}

	model, err := s.loadRoleModel()
	if err != nil {
		return nil, err
	}
	return s.loadSnapshotData(subject, model, rolePermRows)
}

// loadSnapshotData builds the per-subject read model on top of the shared,
// history-free role model and role/permission rows, so reverse queries
// spanning every subject load the global tables only once.
func (s *Service) loadSnapshotData(subject string, model roleModel, rolePermRows []rolePermRow) (*snapshot, error) {
	snap := &snapshot{roleModel: model, rolePerm: rolePermRows}

	bindingVersions, err := s.store.ListBindingVersions(subject)
	if err != nil {
		return nil, err
	}
	for _, version := range bindingVersions {
		snap.bindings = append(snap.bindings, bindingRow{
			seq:           version.Seq,
			roleID:        version.RoleID,
			event:         version.Event,
			occurredAt:    version.OccurredAt,
			effectiveFrom: version.EffectiveFrom,
			effectiveTo:   version.EffectiveTo,
			id:            version.ID,
		})
	}

	scopeVersions, err := s.store.ListScopeVersions(subject)
	if err != nil {
		return nil, err
	}
	for _, version := range scopeVersions {
		parsedScope, ok := parseScope(version.ScopeText)
		if !ok {
			continue
		}
		snap.scopes = append(snap.scopes, scopeRow{
			seq:           version.Seq,
			roleID:        version.RoleID,
			permissionID:  version.PermissionID,
			scope:         parsedScope,
			event:         version.Event,
			occurredAt:    version.OccurredAt,
			effectiveFrom: version.EffectiveFrom,
			effectiveTo:   version.EffectiveTo,
			id:            version.ID,
		})
	}
	return snap, nil
}

// loadRoleModel reads the current inheritance graph and static permission
// operation coverage. Both are present-time definitions without intervals.
func (s *Service) loadRoleModel() (roleModel, error) {
	model := roleModel{
		roleParents:    map[string][]string{},
		permOperations: map[string]map[string]bool{},
	}
	roleIDs, err := s.store.ListCatalog(store.CatalogRole)
	if err != nil {
		return roleModel{}, err
	}
	for _, roleID := range roleIDs {
		parents, err := s.store.RoleParents(roleID)
		if err != nil {
			return roleModel{}, err
		}
		model.roleParents[roleID] = parents
	}

	permissionIDs, err := s.store.ListCatalog(store.CatalogPermission)
	if err != nil {
		return roleModel{}, err
	}
	for _, permissionID := range permissionIDs {
		operations, err := s.store.PermissionOperations(permissionID)
		if err != nil {
			return roleModel{}, err
		}
		set := map[string]bool{}
		for _, operation := range operations {
			set[operation] = true
		}
		model.permOperations[permissionID] = set
	}
	return model, nil
}

// loadRolePermissionRows reads every role/permission grant interval version.
func (s *Service) loadRolePermissionRows() ([]rolePermRow, error) {
	rolePermVersions, err := s.store.ListRolePermissionVersions()
	if err != nil {
		return nil, err
	}
	rows := make([]rolePermRow, 0, len(rolePermVersions))
	for _, version := range rolePermVersions {
		rows = append(rows, rolePermRow{
			seq:           version.Seq,
			roleID:        version.RoleID,
			permissionID:  version.PermissionID,
			event:         version.Event,
			occurredAt:    version.OccurredAt,
			effectiveFrom: version.EffectiveFrom,
			effectiveTo:   version.EffectiveTo,
			id:            version.ID,
		})
	}
	return rows, nil
}

// resolveTimings resolves event and effective times. Both default to now;
// either may be supplied and effectiveFrom need not follow occurredAt.
func (s *Service) resolveTimings(occurredAtText, effectiveFromText string, effectiveField string) (timings, *Failure) {
	now := time.Now().UTC()
	result := timings{occurredAt: FormatTime(now), effectiveFrom: FormatTime(now)}
	if occurredAtText != "" {
		occurred, fail := ParseTime(occurredAtText)
		if fail != nil {
			fail.Field = "occurredAt"
			return timings{}, fail
		}
		result.occurredAt = FormatTime(occurred)
	}
	if effectiveFromText != "" {
		effective, fail := ParseTime(effectiveFromText)
		if fail != nil {
			fail.Field = effectiveField
			return timings{}, fail
		}
		result.effectiveFrom = FormatTime(effective)
	}
	return result, nil
}

// rowActive reports whether the half-open interval [from,to) contains t; an
// empty to marks an open interval.
func rowActive(from, to, at string) bool {
	if from > at {
		return false
	}
	return to == "" || to > at
}
