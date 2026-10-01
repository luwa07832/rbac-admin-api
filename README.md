# rbac-admin-api

把角色、权限点、主体绑定和授权范围记录成可查询的服务。三层关系（主体↔角色归属、
角色↔权限点授权、主体在授权范围内的生效记录）每次新增、修改或撤销都会形成一条可区分的
有效区间，支持按任意时刻回看判定结果与变更历史。

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

## 时间与区间约定

- 所有时间字段均为 RFC3339（含时区），存储与输出统一为 UTC 文本。
- 区间为半开区间 `[effectiveFrom, effectiveTo)`；`effectiveTo` 为 `null` 表示当前仍有效。
- 写入时 `occurredAt`（变更发生时刻）与 `effectiveFrom`（生效时刻）均可选，省略时取服务端
  当前时间；二者允许不一致（补录或预定未来生效）。
- 判定时 `effectiveAt` 可选，省略时表示「当前」。

## 目录与静态定义

标识符使用既有语法：非空、无空白、每段匹配 `[A-Za-z0-9][A-Za-z0-9._:@-]*`，层之间用 `/`
分隔（URL 中需把 `/` 百分号编码为 `%2F`）。

| 方法与路径 | 说明 |
|---|---|
| `PUT /subjects/{id}` | 注册主体（幂等） |
| `PUT /resources/{id}` | 注册资源（幂等） |
| `PUT /operations/{id}` | 注册操作（幂等） |
| `PUT /roles/{id}` | 注册角色（幂等） |
| `PUT /permissions/{id}` | 注册权限点（幂等） |
| `PUT /roles/{id}/parents` | 设定角色继承的父角色集合，请求体 `{"parents":["base"]}`；成环返回 `INVALID_REQUEST` |
| `PUT /permissions/{id}/operations` | 设定权限点静态覆盖的操作集合，请求体 `{"operations":["read"]}`，至少一个 |

## 三层有效区间

对同一身份重复新增当前仍有效的区间返回 `CONFLICT`；撤销或修改不存在的当前区间返回
`NOT_FOUND`。所有写入请求体都是 JSON 对象，均可选携带 `occurredAt` 与 `effectiveFrom`。

### 主体↔角色归属

| 方法与路径 | event | 说明 |
|---|---|---|
| `PUT /subjects/{subject}/bindings/{role}` | `GRANT` | 新增一条角色归属区间 |
| `PATCH /subjects/{subject}/bindings/{role}` | `UPDATE` | 请求体 `{"newRole":"editor", ...}`，关闭旧角色区间并在新角色上开启区间 |
| `DELETE /subjects/{subject}/bindings/{role}` | `REVOKE` | 关闭区间并记录零长度撤销事件 |

### 角色↔权限点授权

| 方法与路径 | event | 说明 |
|---|---|---|
| `PUT /roles/{role}/permissions/{permission}` | `GRANT` | 新增角色的权限点授权区间 |
| `PATCH /roles/{role}/permissions/{permission}` | `UPDATE` | 请求体 `{"newRole":...,"newPermission":...}` |
| `DELETE /roles/{role}/permissions/{permission}` | `REVOKE` | 关闭授权区间 |

### 授权范围

请求体标识目标并给出范围：`{"role":"viewer","scope":"tenant-a/*"}` 或
`{"permission":"doc-read","scope":"tenant-a/doc-1"}`，二者必须且只能设置一个。

| 方法与路径 | event | 说明 |
|---|---|---|
| `PUT /subjects/{subject}/scopes` | `GRANT` | 新增授权范围区间 |
| `PATCH /subjects/{subject}/scopes` | `UPDATE` | 请求体同时携带旧目标 `role/permission/scope` 与新目标 `newRole/newPermission/newScope` |
| `DELETE /subjects/{subject}/scopes` | `REVOKE` | 关闭授权范围区间 |

范围语法沿用既有边界：`*` 全部资源；`前缀/*` 表示该前缀 `/` 之下的资源；其余为精确资源。

## `POST /authorize`

按可选时刻对「主体 / 资源 / 操作」三元组给出判定。省略 `effectiveAt` 时返回当前结果。

请求体：

```json
{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","effectiveAt":"2026-02-01T00:00:00Z"}
```

授权时：

```json
{"decision":{"granted":true,"matchedRole":"viewer","matchedPermission":"doc-read","matchedScope":"tenant-a/*"}}
```

直接权限点授权（不经过角色）命中时 `matchedRole` 为 `null`。拒绝时只有两个字段：

```json
{"decision":{"granted":false,"reason":"OUT_OF_SCOPE"}}
```

拒绝原因按层级固定取值：

| reason | 含义 |
|---|---|
| `NO_ROLE_BINDING` | 主体从未有过（或当前没有）可到达的角色归属，且不存在直接权限点授权 |
| `NO_PERMISSION_BINDING` | 有角色归属但角色链上没有覆盖该操作的权限点授权，也没有直接权限点授权 |
| `OUT_OF_SCOPE` | 权限点覆盖操作，但没有任何授权范围模式覆盖目标资源 |
| `NOT_EFFECTIVE` | 三层中某一层历史上存在但在 `effectiveAt` 时刻不处于有效区间内 |

层级判定遵循「先看当前是否全链路有效；否则按归属→权限点→范围顺序，第一层历史存在但
当前失效的关系产出 `NOT_EFFECTIVE`，从未存在才产出对应结构性原因」；直接权限点授权跳过
角色层。同一时刻命中多条时，范围更具体者优先（精确 > 更长前缀 > 前缀 > `*`），再按权限点、
角色标识字典序决胜。

## `GET /history`

按三元组查询与之相关的授权变更，按 `effectiveFrom` 从早到晚排列；同一时刻按 `occurredAt`
稳定排序，再以全局写入序号决胜。可选半开区间参数 `from`、`to`（按 `effectiveFrom` 过滤）。

```
GET /history?subject=user-1&resource=tenant-a%2Fdoc-1&operation=read&from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z
```

```json
{"events":[
  {"event":"GRANT","occurredAt":"2026-01-01T00:00:00Z","effectiveFrom":"2026-01-01T00:00:00Z","effectiveTo":null,
   "role":"viewer","permission":"doc-read","scope":"tenant-a/*","granted":true}
]}
```

- `event` 限于 `GRANT`、`UPDATE`、`REVOKE`；撤销事件的 `effectiveFrom` 与 `effectiveTo` 相同。
- 与该三元组无关的变更不返回；无匹配记录返回 `{"events":[]}`。
- 每项的 `granted` 表示该变更生效瞬间三元组的判定结论；不适用的 `role`/`permission`/`scope`
  为 `null`。

## 错误约定

所有错误响应都是单个顶层 `error` 对象：

```json
{"error":{"type":"NOT_FOUND","field":"subject","message":"subject does not exist"}}
```

| error.type | HTTP | 触发情形 |
|---|---|---|
| `NOT_FOUND` | 404 | 主体、资源、操作（或写入引用的角色、权限点）不存在，`field` 标明 `subject`/`resource`/`operation`/`role`/`permission` |
| `INVALID_TIME` | 400 | 时间字段不是合法 RFC3339 或超出支持范围 |
| `INVALID_RANGE` | 400 | 历史查询区间起点晚于终点 |
| `INVALID_REQUEST` | 400 | 空请求体、JSON 语法/类型错误、未知字段、非法标识符或范围、引用缺失、角色继承成环等 |
| `CONFLICT` | 409 | 同一身份已存在当前有效的区间 |

健康检查入口 `GET /healthz` 保持原有形态：正常返回
`{"status":"ok","database":"ok"}`；存储不可用时 HTTP 503 返回
`{"error":{"code":"storage_unavailable","message":"database is not available"}}`。
未知路由仍返回 `route_not_found`。
