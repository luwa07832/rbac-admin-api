package authz

import "github.com/luwa07832/rbac-admin-api/internal/store"

func invalidRequest(field, message string) *Failure {
	return failure(TypeInvalidRequest, field, message)
}

// requireIdentifiers validates the subject/resource/operation triple grammar.
func requireIdentifiers(subject, resource, operation string) *Failure {
	if !validIdentifier(subject) {
		return invalidRequest("subject", "field subject is not a parseable identifier")
	}
	if !validIdentifier(resource) {
		return invalidRequest("resource", "field resource is not a parseable identifier")
	}
	if !validIdentifier(operation) {
		return invalidRequest("operation", "field operation is not a parseable identifier")
	}
	return nil
}

// checkTriple reports the first unknown member of the triple in the published
// order subject, resource, operation.
func (s *Service) checkTriple(subject, resource, operation string) *Failure {
	for _, check := range []struct {
		kind  store.CatalogKind
		id    string
		field string
	}{
		{store.CatalogSubject, subject, "subject"},
		{store.CatalogResource, resource, "resource"},
		{store.CatalogOperation, operation, "operation"},
	} {
		exists, err := s.store.Exists(check.kind, check.id)
		if err != nil {
			return failure(TypeInvalidRequest, check.field, "could not verify "+check.field)
		}
		if !exists {
			return failure(TypeNotFound, check.field, check.field+" does not exist")
		}
	}
	return nil
}
