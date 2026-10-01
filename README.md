# rbac-admin-api

把角色、权限点、主体绑定和授权范围记录成可查询的服务，支持判定某主体在指定资源与操作上是否被授权，并可按时间回看授权变化与历史决策。

## 运行要求

- Go 1.26 或以上
- SQLite（本服务自带存储，不需要外部数据库）

## 构建、测试与启动

```bash
go build ./...
go test ./...
go run .
```

服务默认监听 `127.0.0.1:8080`。可用环境变量覆盖：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `ADDR` | `127.0.0.1:8080` | HTTP 监听地址 |
| `DB_PATH` | `rbac-admin-api.db` | SQLite 数据库文件路径 |

## 数据模型与时间区间

- 主体（subjects）、资源（resources）、操作（operations）、权限点（permissions）、角色（roles）各自由调用方用字符串标识创建。
- 权限点通过 `permission_operations` 覆盖一个或多个操作。
- 角色可通过 `role_inheritance` 继承其他角色（拒绝形成环）。
- 三层随时间版本化的关系，每条关系都带一个左闭右开的有效区间 `[effectiveFrom, effectiveTo)`，`effectiveTo` 为空表示当前仍有效：
  1. **角色归属**：主体绑定角色（`subject_role_intervals`），每条绑定带一个授权范围；
  2. **权限点授权**：角色拥有权限点（`role_permission_intervals`）；
  3. **直接授权**：主体直接获得带范围的权限点（`direct_grant_intervals`）。
- 每次新增打开新区间；撤销在撤销时刻关闭当前区间；修改绑定范围会在同一时刻关闭旧区间并打开新区间（关闭原因为 `update`）。同一关系在仍有效时重复新增是幂等的，不产生新区间。
- 判定某时刻是否授权时，三层关系都必须存在在该时刻仍有效的重叠区间。
- 授权范围有三种，均按资源标识文本匹配：
  - `exact`：值与资源标识完全相等。
  - `prefix`：值必须以 `/` 结尾，匹配该层级段本身及其下级（如 `docs/` 匹配 `docs`、`docs/a`，不匹配 `docsx`）。
  - `all`：覆盖任意资源，值必须为空字符串。

## 已公开的入口

### `GET /healthz`

返回服务与存储状态。正常时 HTTP 200：

```json
{"status":"ok","database":"ok"}
```

存储不可用时 HTTP 503：

```json
{"error":{"code":"storage_unavailable","message":"database is not available"}}
```

### 判定：`GET/POST /api/v1/authorize`

在不修改任何记录的前提下，判定主体在资源与操作上的授权结论；支持按可选时刻 `effectiveAt` 回看历史决策。省略 `effectiveAt` 时按当前时刻判定。

`POST` 请求体（字段恰好为下列键，不允许额外、重复字段；`effectiveAt` 可选）：

```json
{"subject":"carol","resource":"docs/plan","operation":"approve","effectiveAt":"2025-03-01T08:00:00Z"}
```

`GET` 使用同名查询参数：`/api/v1/authorize?subject=carol&resource=docs/plan&operation=approve&effectiveAt=...`（不允许重复或多余参数）。

`effectiveAt` 必须是 RFC3339 时间（如 `2025-03-01T08:00:00Z` 或带偏移的 `2025-03-01T16:00:00+08:00`）。

**存在性检查（固定顺序：主体 → 资源 → 操作）**，任一不存在返回独立错误，绝不当作无权：

```json
{"error":{"type":"NOT_FOUND","field":"subject","message":"the subject does not exist"}}
```

`field` 取值为 `subject`、`resource`、`operation`，HTTP 404。时间格式无法解析或超出支持范围时返回 HTTP 400：

```json
{"error":{"type":"INVALID_TIME","field":"effectiveAt","message":"..."}}
```

**判定结果始终为 HTTP 200**。被授权时只返回命中的三层关系，未授权时只返回一个稳定 `reason`：

```json
{
  "subject": "carol",
  "resource": "docs/plan",
  "operation": "approve",
  "granted": true,
  "matchedRole": "approver",
  "matchedPermission": "can-approve",
  "matchedScope": {"kind": "prefix", "value": "docs/"}
}
```

直接授权命中时 `matchedRole` 为 `null`。提供了 `effectiveAt` 时响应原样回显该字段。未授权响应示例：

```json
{"subject":"carol","resource":"docs/plan","operation":"approve","granted":false,"reason":"OUT_OF_SCOPE"}
```

`reason` 取值与固定检查顺序：

| reason | 含义 |
|---|---|
| `NO_ROLE_BINDING` | 主体在任何时刻都没有角色绑定或直接授权 |
| `NO_PERMISSION_BINDING` | 存在绑定/授权，但没有权限点（经角色继承）覆盖目标操作 |
| `OUT_OF_SCOPE` | 存在覆盖操作的权限点，但所有副本的范围都不覆盖目标资源 |
| `NOT_EFFECTIVE` | 三层结构都匹配，但在 `effectiveAt` 时刻没有同时有效的重叠区间 |

结构层（角色归属、权限点授权、授权范围）先于时间判断；多条有效授权同时命中时选择范围更具体的一条：`exact` 优先于 `prefix`，`prefix` 优先于 `all`，再依次按范围值长度、范围值、角色标识、权限标识、授权方式决胜。

### 授权变更历史：`GET/POST /api/v1/history`

按主体、资源、操作查询与该三元组相关的授权变化，按生效时刻从早到晚返回；同一时刻的变更按内部写入序号稳定排序。

- `GET`：`/api/v1/history?subject=carol&resource=docs/plan&operation=approve&from=...&to=...`
- `POST`：`{"subject":"...","resource":"...","operation":"...","effectiveFrom":"...","effectiveTo":"..."}`
- 时间区间可选，短名 `from`/`to` 与长名 `effectiveFrom`/`effectiveTo` 等价但不得混用，按 `occurredAt` 闭区间过滤；无匹配记录返回空列表 `{"events":[]}`。
- 起点晚于终点返回 HTTP 400：`{"error":{"type":"INVALID_RANGE",...}}`；时间格式错误返回 `INVALID_TIME`；主体、资源、操作不存在时与判定入口相同返回 `NOT_FOUND`。

每个事件包含固定字段：

```json
{
  "event": "GRANT",
  "occurredAt": "2025-03-01T08:00:00Z",
  "effectiveFrom": "2025-03-01T08:00:00Z",
  "effectiveTo": null,
  "role": "approver",
  "permission": "can-approve",
  "scope": {"kind": "prefix", "value": "docs/"},
  "granted": true
}
```

- `event`：`GRANT`（变得可访问，区间开始）、`UPDATE`（仍可访问但绑定范围变更）、`REVOKE`（变得不可访问）。
- `effectiveTo` 为 `null` 表示该授权区间当前仍有效；撤销事件的起止时刻为撤销当时。
- 直接授权相关事件 `role` 为 `null`。

### 记录管理（`/api/v1` 前缀）

| 方法与路径 | 用途 |
|---|---|
| `POST /api/v1/{subjects,resources,operations,permissions,roles}` | 创建记录，体：`{"id":"...","name":"..."}`，成功 201 |
| `GET /api/v1/{...}` | 列出该类全部记录 |
| `GET /api/v1/{...}/:id` | 查询单条记录，不存在 404 |
| `PUT /api/v1/{...}/:id` | 修改名称，体：`{"name":"..."}` |
| `DELETE /api/v1/{...}/:id` | 删除记录；仍被引用时 409 |
| `POST /api/v1/permissions/:id/operations` | 权限点覆盖操作，体：`{"id":"<operation>"}` |
| `DELETE /api/v1/permissions/:id/operations/:operationId` | 取消覆盖 |
| `POST /api/v1/roles/:id/permissions` | 角色获得权限点（打开有效区间），体：`{"id":"<permission>"}` |
| `DELETE /api/v1/roles/:id/permissions/:permissionId` | 撤销角色对权限点的授权（关闭区间） |
| `POST /api/v1/roles/:id/parents` | 角色继承父角色，体：`{"id":"<parentRole>"}`；成环 409 |
| `DELETE /api/v1/roles/:id/parents/:parentId` | 取消继承 |
| `POST /api/v1/subjects/:id/roles` | 绑定角色并打开有效区间，体：`{"role":"...","scope":{...}}`；重复幂等 204 |
| `PUT /api/v1/subjects/:id/roles/:roleId?scope_kind=...&scope_value=...` | 修改一条开放绑定的范围（同一时刻关旧开新，历史记为 UPDATE），体：`{"scope":{...}}` |
| `DELETE /api/v1/subjects/:id/roles/:roleId?scope_kind=...&scope_value=...` | 撤销一条带范围的绑定（关闭区间） |
| `POST /api/v1/subjects/:id/grants` | 直接授权并打开有效区间，体：`{"permission":"...","scope":{...}}`；重复幂等 204 |
| `DELETE /api/v1/subjects/:id/grants/:permissionId?scope_kind=...&scope_value=...` | 撤销一条直接授权（关闭区间） |

引用不存在记录返回 404；外键冲突、重复值冲突、非法范围返回 409 或 400。

## 错误约定

所有错误响应都是单个顶层 `error` 对象。时间化查询入口（`/authorize`、`/history` 的主体、资源、操作与时间问题）使用 `type`（以及适用时的 `field`）；其余管理与健康入口继续使用 `code` 与 `message` 两个字符串字段。`message` 不包含 SQL、堆栈或文件路径。业务码还包括 `route_not_found`（404）、`method_not_allowed`（405）、`invalid_request`（400）和 `storage_unavailable`（503）。
