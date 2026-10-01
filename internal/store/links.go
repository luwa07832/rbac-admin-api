package store

var linkInsert = map[string]string{
	"permission_operations": `INSERT INTO permission_operations (permission_id, operation_id)
		VALUES (?, ?) ON CONFLICT DO NOTHING`,
	"role_inheritance": `INSERT INTO role_inheritance (role_id, parent_id)
		VALUES (?, ?) ON CONFLICT DO NOTHING`,
}

var linkDelete = map[string]string{
	"permission_operations": `DELETE FROM permission_operations
		WHERE permission_id = ? AND operation_id = ?`,
	"role_inheritance": `DELETE FROM role_inheritance
		WHERE role_id = ? AND parent_id = ?`,
}
