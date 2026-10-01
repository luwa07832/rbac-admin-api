package authz

func indexPermissionOperations(links []PermissionOperation, operation string) map[string]bool {
	covers := make(map[string]bool)
	for _, link := range links {
		if link.Operation == operation {
			covers[link.Permission] = true
		}
	}
	return covers
}

// authzInterval is one open/closed window of a role-permission authorization.
type authzInterval struct {
	Permission string
	From       int64
	To         int64
	HasTo      bool
	Seq        int64
}

func indexRolePermissionVersions(links []RolePermissionVersion) map[string][]authzInterval {
	owns := make(map[string][]authzInterval)
	for _, link := range links {
		owns[link.Role] = append(owns[link.Role], authzInterval{
			Permission: link.Permission,
			From:       link.From,
			To:         link.To,
			HasTo:      link.HasTo,
			Seq:        link.Seq,
		})
	}
	return owns
}

// reachableRoles returns, for every role, the role itself followed by every
// role reachable through inheritance. Cycles cannot make the traversal
// infinite thanks to the in-progress memo entry.
func reachableRoles(edges []RoleParent) map[string][]string {
	parents := make(map[string][]string)
	for _, edge := range edges {
		parents[edge.Role] = append(parents[edge.Role], edge.Parent)
	}
	reachable := make(map[string][]string)
	for role := range parents {
		collectRoles(role, parents, reachable)
	}
	return reachable
}

func collectRoles(role string, parents map[string][]string, memo map[string][]string) []string {
	if seen, ok := memo[role]; ok {
		return seen
	}
	memo[role] = []string{} // guard against cycles
	order := []string{role}
	for _, parent := range parents[role] {
		for _, ancestor := range collectRoles(parent, parents, memo) {
			order = appendRoleOnce(order, ancestor)
		}
	}
	memo[role] = order
	return order
}

func appendRoleOnce(order []string, role string) []string {
	for _, existing := range order {
		if existing == role {
			return order
		}
	}
	return append(order, role)
}
