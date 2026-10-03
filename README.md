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

## `POST /authorize/batch`

在同一个时刻批量判定多组「主体 / 资源 / 操作」三元组。请求体只含可选的 `effectiveAt`
与必填的 `queries`；`effectiveAt` 省略（或为 `null`）时表示当前时刻，否则是整批共用的
RFC3339 时刻，输出规范化为 UTC。`queries` 是 1 到 100 项的数组，每项只含 `subject`、
`resource`、`operation` 三个字符串字段，标识符沿用既有语法。

```json
{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
  {"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
  {"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"}]}
```

成功返回 200，顶层为 `decisions` 数组，顺序与 `queries` 完全一致，重复三元组不合并：

```json
{"decisions":[
  {"subject":"user-1","resource":"tenant-a/doc-1","operation":"read",
   "decision":{"granted":true,"matchedRole":"viewer","matchedPermission":"doc-read","matchedScope":"tenant-a/*"}},
  {"subject":"user-2","resource":"tenant-a/doc-1","operation":"read",
   "decision":{"granted":false,"reason":"NO_ROLE_BINDING"}}]}
```

- 每项都回显自己的 `subject`、`resource`、`operation` 与 `decision`；`decision` 与同一
  `effectiveAt` 调用 `POST /authorize` 的结果逐字段一致：获权时为 `granted true` 加
  `matchedRole`、`matchedPermission`、`matchedScope`（直接权限点命中时 `matchedRole` 为
  `null`），拒绝时只有 `granted false` 与 `reason`，`reason` 固定为 `NO_ROLE_BINDING`、
  `NO_PERMISSION_BINDING`、`OUT_OF_SCOPE`、`NOT_EFFECTIVE` 之一。
- 角色继承、权限点静态覆盖、范围匹配与半开区间语义全部沿用单笔判定；无人获权是正常
  decision，不视为错误。
- 校验顺序固定：先校验整批结构与时间，再按下标逐项校验。任一异常都只返回单个 `error`
  对象，不返回部分 `decisions`。
- `queries` 缺失、不是数组、为空或超过 100 项，请求体不是 JSON 对象、含未知顶层字段，
  均返回 `INVALID_REQUEST`（`field` 为 `queries` 或该未知字段名）；`effectiveAt` 给定时
  必须是 RFC3339 字符串，非法或超范围返回 `INVALID_TIME`（`field` 为 `effectiveAt`），
  并优先于一切单项检查；但整批结构错误仍优先于 `effectiveAt`。
- 单项不是对象、缺字段、多字段（含未知字段）或字段类型错误返回 `INVALID_REQUEST`；
  标识符非法返回 `INVALID_REQUEST`；合法但未注册返回 `NOT_FOUND`。单项按
  subject、resource、operation 顺序检查，`field` 使用 `queries[0].subject` 这样的定位值，
  下标从 0 开始并按数组顺序报告首个问题。

## `POST /authorize/batch/explain`

在同一个时刻批量解释多组「主体 / 资源 / 操作」三元组的判定与全部授权路径。请求体沿用
`POST /authorize/batch`：只含可选的 `effectiveAt` 与必填的 `queries`；`effectiveAt` 省略
（或为 `null`）时表示当前时刻，否则是整批共用的 RFC3339 时刻，输出规范化为 UTC。
`queries` 是 1 到 100 项的数组，每项只含 `subject`、`resource`、`operation` 三个字符串
字段，标识符沿用既有语法。入口只读，不写有效区间或变更历史，不影响后续授权判定。

```json
{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
  {"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
  {"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"}]}
```

成功返回 200，顶层为规范化的 `effectiveAt` 与 `explanations` 数组，后者顺序与 `queries`
完全一致，重复三元组不合并；每项回显自己的 `subject`、`resource`、`operation`、`decision`
与 `paths`：

```json
{"effectiveAt":"2026-02-01T00:00:00Z","explanations":[
  {"subject":"user-1","resource":"tenant-a/doc-1","operation":"read",
   "decision":{"granted":true,"matchedRole":null,"matchedPermission":"doc-read","matchedScope":"tenant-a/doc-1"},
   "paths":[
    {"source":"DIRECT_PERMISSION","boundRole":null,"role":null,"permission":"doc-read","scope":"tenant-a/doc-1"},
    {"source":"ROLE","boundRole":"viewer","role":"base","permission":"doc-read","scope":"tenant-a/*"}]},
  {"subject":"user-2","resource":"tenant-a/doc-1","operation":"read",
   "decision":{"granted":false,"reason":"NO_ROLE_BINDING"},"paths":[]}]}
```

- `decision` 与同一 `effectiveAt` 调用 `POST /authorize` 的结果逐字段一致：获权时为
  `granted true` 加 `matchedRole`、`matchedPermission`、`matchedScope`（直接权限点命中时
  `matchedRole` 为 `null`），拒绝时只有 `granted false` 与 `reason`，`reason` 固定为
  `NO_ROLE_BINDING`、`NO_PERMISSION_BINDING`、`OUT_OF_SCOPE`、`NOT_EFFECTIVE` 之一。
- `paths` 与同一时刻调用 `POST /authorize/explain` 的结果逐字段一致：每项固定为
  `source`、`boundRole`、`role`、`permission`、`scope`，保留 `DIRECT_PERMISSION`、`ROLE`、
  `boundRole`、`role`、`permission`、`scope` 结构与资源反查的稳定排序，按完整字段组合
  去重，多条同时命中时全部返回。
- 授权时 `decision.granted` 为 `true` 且 `paths` 非空；拒绝时 `decision.granted` 为
  `false` 且 `paths` 为空数组。角色继承、权限点静态覆盖、范围匹配与半开区间语义全部沿用
  单笔判定；无人获权是正常结果，不视为错误。
- 整批原子返回。校验顺序固定：先校验整批结构，再校验共用的 `effectiveAt`，最后按下标逐项
  校验；任一异常都只返回单个 `error` 对象和 400 或 404，不返回部分 `explanations`。
- 请求体不是 JSON 对象、含未知顶层字段，或 `queries` 缺失、不是数组、为空、超过 100 项，
  均返回 `INVALID_REQUEST`（`field` 为 `queries` 或该未知字段名），且整批结构错误优先于
  `effectiveAt`；`effectiveAt` 已给出但不是字符串、不是合法 RFC3339 时间或超出支持范围时
  唯一返回 `INVALID_TIME`（`field` 为 `effectiveAt`），并优先于一切单项检查。
- 单项不是对象、缺字段、多字段（含未知字段）或字段类型错误返回 `INVALID_REQUEST`；
  标识符非法返回 `INVALID_REQUEST`；三元组合法但目录不存在时返回 `NOT_FOUND`。单项按
  subject、resource、operation 顺序检查，`field` 使用 `queries[0].subject` 这样的定位值，
  下标从 0 开始并按数组顺序报告首个问题。

## `POST /authorize/explain`

只读解释一次授权判定：请求体沿用 `POST /authorize` 的 `subject`、`resource`、`operation`
与可选 `effectiveAt`，返回判定结论之外还列出该时刻完整覆盖资源与操作的全部授权路径。
不写有效区间或变更历史，空命中正常返回。

```json
{"effectiveAt":"2026-02-01T00:00:00Z",
 "decision":{"granted":true,"matchedRole":"viewer","matchedPermission":"doc-read","matchedScope":"tenant-a/*"},
 "paths":[
  {"source":"DIRECT_PERMISSION","boundRole":null,"role":null,"permission":"doc-read","scope":"tenant-a/doc-1"},
  {"source":"ROLE","boundRole":"viewer","role":"base","permission":"doc-read","scope":"tenant-a/*"}]}
```

- `effectiveAt` 是判定时刻的 RFC3339 UTC 文本，输入省略时取服务当前时刻；`decision`
  与同一时刻调用 `POST /authorize` 的结果完全一致，多条同时命中时只报告既有优先级选出
  的匹配。
- `paths` 每项固定为 `source`、`boundRole`、`role`、`permission`、`scope`，沿用资源反查
  的口径：`DIRECT_PERMISSION` 跳过角色层，两个角色字段均为 `null`；`ROLE` 项的
  `boundRole` 是主体直接绑定的角色，`role` 是经继承实际承载权限点的角色。路径按完整
  字段组合去重，并沿用资源反查的稳定排序；多条同时命中时全部返回。
- 授权时 `paths` 非空且 `decision.granted` 为 `true`；拒绝时 `paths` 为空数组，
  `decision.granted` 为 `false`，`reason` 固定为 `NO_ROLE_BINDING`、
  `NO_PERMISSION_BINDING`、`OUT_OF_SCOPE`、`NOT_EFFECTIVE` 之一。
- 请求体不是 JSON 对象、缺必填字段、含未知字段或标识符不合既有语法时返回
  `INVALID_REQUEST`；合法但目录不存在返回 `NOT_FOUND`，`field` 按 `subject`、
  `resource`、`operation` 指明首个问题。`effectiveAt` 非法或超范围时唯一返回
  `INVALID_TIME`（`field` 为 `effectiveAt`），并优先于三元组检查。

## `GET /subjects/{id}/access`

按可选时刻列出主体生效的授权路径（只读，不写入历史记录）。省略 `effectiveAt` 时查询当前
时刻；含 `/` 的主体标识符同样写作 `%2F`。

```
GET /subjects/user-1/access?effectiveAt=2026-02-01T00:00:00Z
```

```json
{"access":[
  {"source":"DIRECT_PERMISSION","boundRole":null,"role":null,"permission":"doc-read","operations":["read"],"scope":"tenant-a/doc-1"},
  {"source":"ROLE","boundRole":"viewer","role":"base","permission":"doc-read","operations":["read"],"scope":"tenant-a/*"}
]}
```

- 只列出在 `effectiveAt` 同时满足主体角色归属、角色到权限点授权、主体授权范围三层有效
  区间的路径。
- `source` 限于 `ROLE` 与 `DIRECT_PERMISSION`。`ROLE` 项的 `boundRole` 是主体直接绑定的
  角色，`role` 是经继承实际承载权限点的角色；`DIRECT_PERMISSION` 项跳过角色层，
  `boundRole` 与 `role` 均为 `null`。
- `operations` 是该权限点覆盖操作的去重集合，按标识符字典序排列。
- 相同的 `source`、`boundRole`、`role`、`permission`、`operations`、`scope` 组合只返回一次；
  数组按该字段顺序排序。
- 没有任何生效路径时返回 `{"access":[]}`，不视为错误。
- 主体不存在返回 `NOT_FOUND`（`field` 为 `subject`），路径标识符非法返回
  `INVALID_REQUEST`（`field` 为 `subject`）；`effectiveAt` 不是合法 RFC3339 或超出支持
  范围时唯一返回 `INVALID_TIME`（`field` 为 `effectiveAt`）。

## `GET /subjects/{id}/access/diff`

只读对比某主体在两个时刻之间生效授权路径的变化，不写入变更历史。`from` 与 `to` 均必填，
为 RFC3339 时间，分别给出比较的起点与终点；含 `/` 的主体标识符同样写作 `%2F`。起点等于
终点时正常返回。

```
GET /subjects/user-1/access/diff?from=2026-01-01T00:00:00Z&to=2026-04-01T00:00:00Z
```

```json
{"from":"2026-01-01T00:00:00Z","to":"2026-04-01T00:00:00Z",
 "added":[
  {"source":"DIRECT_PERMISSION","boundRole":null,"role":null,"permission":"doc-read","operations":["read"],"scope":"tenant-b/doc-2"}],
 "removed":[],
 "unchanged":[
  {"source":"ROLE","boundRole":"viewer","role":"base","permission":"doc-read","operations":["read"],"scope":"tenant-a/*"}]}
```

- `from`、`to` 回显规范化后的 UTC 时间；按半开有效区间语义分别取两个时刻生效的路径。
- `added` 仅在 `to` 时刻存在，`removed` 仅在 `from` 时刻存在，`unchanged` 在两个时刻都
  存在。路径对象沿用 access 的 `source`、`boundRole`、`role`、`permission`、`operations`、
  `scope` 结构，以完整组合判同一路径并去重；各数组沿用 access 的稳定排序。没有变化时
  三个数组均为空，不视为错误。
- `from` 或 `to` 未提供、为空时返回 `INVALID_REQUEST`（`field` 分别为 `from`、`to`）；
  值非法或超出支持范围时返回 `INVALID_TIME`，`from` 优先于 `to`；`from` 晚于 `to` 返回
  `INVALID_RANGE`。时间参数校验之后，主体标识符非法返回 `INVALID_REQUEST`
  （`field` 为 `subject`），合法但不存在返回 `NOT_FOUND`（`field` 为 `subject`）。

## `GET /roles/{role}/permissions`

脱离具体主体直接核对角色定义（只读，不写入历史记录）。省略 `effectiveAt` 时查询当前
时刻；含 `/` 的角色标识符同样写作 `%2F`。角色继承关系没有历史区间，因此父关系展开始终
使用当前继承图，只有角色与权限点授权按 `effectiveAt` 过滤。

```
GET /roles/viewer/permissions?effectiveAt=2026-02-01T00:00:00Z
```

```json
{"effectiveAt":"2026-02-01T00:00:00Z","role":"viewer","parents":["base","mid"],
 "inheritedRoles":["base","mid"],"permissions":[
  {"role":"base","permission":"doc-read","operations":["read"],"source":"INHERITED"},
  {"role":"viewer","permission":"doc-read","operations":["read"],"source":"DIRECT"}]}
```

- `parents` 是直接父角色，`inheritedRoles` 是从目标角色沿当前父关系可到达的全部祖先；
  二者均按标识符字典序排列且不含目标角色，任一为空返回空数组。
- `permissions` 展开目标角色及祖先角色在该时刻生效的权限点；`role` 是实际承载权限点的
  角色，`operations` 是该权限点静态覆盖操作的去重字典序集合。目标角色自身授权的 `source`
  为 `DIRECT`，祖先角色授权为 `INHERITED`。
- 权限项按 `role`、`permission`、`operations` 稳定排序；没有生效权限点时返回
  `{"permissions":[], ...}`，不视为错误。
- 角色不存在返回 `NOT_FOUND`（`field` 为 `role`），路径标识符非法返回
  `INVALID_REQUEST`（`field` 为 `role`）；`effectiveAt` 非法或超出范围时唯一返回
  `INVALID_TIME`（`field` 为 `effectiveAt`），并优先于角色检查。

## `GET /resources/{resource}/subjects`

反向查询：列出在指定时刻对「资源 / 操作」获权的全部主体（只读，不写入历史记录）。
省略 `effectiveAt` 时查询当前时刻；资源标识符含 `/` 时同样写作 `%2F`，操作通过查询
参数 `operation` 传入。

```
GET /resources/tenant-a%2Fdoc-1/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z
```

```json
{"effectiveAt":"2026-02-01T00:00:00Z","resource":"tenant-a/doc-1","operation":"read",
 "subjects":[
  {"subject":"user-1","paths":[
    {"source":"DIRECT_PERMISSION","boundRole":null,"role":null,"permission":"doc-read","scope":"tenant-a/doc-1"},
    {"source":"ROLE","boundRole":"viewer","role":"base","permission":"doc-read","scope":"tenant-a/*"}]}]}
```

- 只列出在 `effectiveAt` 同时满足主体角色归属、角色到权限点授权（或直接权限点授权）、
  主体授权范围三层有效区间的主体；范围模式（精确、`前缀/*`、`*`）须覆盖目标资源，
  权限点须静态覆盖目标操作，角色路径沿当前继承图可达。
- `subjects` 按主体标识符字典序排列；每项的 `paths` 去重后按 `source`、`boundRole`、
  `role`、`permission`、`scope` 稳定排序。`source` 限于 `ROLE` 与 `DIRECT_PERMISSION`：
  `ROLE` 项的 `boundRole` 是主体直接绑定的角色，`role` 是经继承实际承载权限点的角色；
  `DIRECT_PERMISSION` 跳过角色层，两个角色字段均为 `null`。
- 没有获权主体时返回 `{"subjects":[], ...}`，不视为错误。
- `effectiveAt` 不是合法 RFC3339 或超出支持范围时唯一返回 `INVALID_TIME`（`field` 为
  `effectiveAt`），并优先于其他检查；资源标识符非法或 `operation` 缺失、标识符非法
  返回 `INVALID_REQUEST`（`field` 分别为 `resource`、`operation`）；合法但不存在返回
  `NOT_FOUND`（`field` 分别为 `resource`、`operation`）。

## `GET /resources/{resource}/subjects/diff`

只读对比某「资源 / 操作」在两个时刻之间获权主体及其授权路径的变化，不写入变更历史。
`from` 与 `to` 均必填，为 RFC3339 时间，分别给出比较的起点与终点；资源标识符沿用既有
语法，含 `/` 时写作 `%2F`，操作通过查询参数 `operation` 传入。起点等于终点时正常返回，
全部路径进入 `unchanged`。

```
GET /resources/tenant-a%2Fdoc-1/subjects/diff?operation=read&from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z
```

```json
{"from":"2026-02-01T00:00:00Z","to":"2026-04-01T00:00:00Z","resource":"tenant-a/doc-1","operation":"read",
 "subjects":[
  {"subject":"user-1",
   "added":[{"source":"DIRECT_PERMISSION","boundRole":null,"role":null,"permission":"doc-read","scope":"tenant-a/doc-1"}],
   "removed":[{"source":"ROLE","boundRole":"editor","role":"editor","permission":"doc-read","scope":"*"}],
   "unchanged":[{"source":"ROLE","boundRole":"viewer","role":"base","permission":"doc-read","scope":"tenant-a/*"}]}]}
```

- 每个时刻都按资源反查的既有语义筛选：主体角色归属、沿当前父关系可达的角色权限点授权
  （或直接权限点授权）、权限点静态覆盖 `operation` 且授权范围覆盖 `resource`，三层均处于
  半开有效区间内。
- 路径对象沿用资源反查的 `source`、`boundRole`、`role`、`permission`、`scope` 结构，以
  完整字段组合判同一路径并去重；`added` 仅含 `to` 时刻存在的路径，`removed` 仅含 `from`
  时刻存在的路径，`unchanged` 含两个时刻都存在的路径。
- `subjects` 按主体标识符字典序排列并含任一时刻存在路径的主体；各数组沿用资源反查的
  稳定排序。没有任何主体获权时返回 `{"subjects":[]}`，空差异返回 200，均不视为错误。
- `from` 或 `to` 未提供、为空时返回 `INVALID_REQUEST`（`field` 分别为 `from`、`to`）；
  值非法或超出支持范围时返回 `INVALID_TIME`，`from` 优先于 `to`；`from` 晚于 `to` 返回
  `INVALID_RANGE`。时间参数校验之后，资源标识符非法或 `operation` 缺失、标识符非法返回
  `INVALID_REQUEST`（`field` 分别为 `resource`、`operation`）；合法但未注册返回 `NOT_FOUND`
  （`field` 分别为 `resource`、`operation`）。查询只读，不改变后续授权判定。

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
| `INVALID_RANGE` | 400 | 历史或差异查询区间起点晚于终点 |
| `INVALID_REQUEST` | 400 | 空请求体、JSON 语法/类型错误、未知字段、非法标识符或范围、引用缺失、角色继承成环等 |
| `CONFLICT` | 409 | 同一身份已存在当前有效的区间 |

健康检查入口 `GET /healthz` 保持原有形态：正常返回
`{"status":"ok","database":"ok"}`；存储不可用时 HTTP 503 返回
`{"error":{"code":"storage_unavailable","message":"database is not available"}}`。
未知路由仍返回 `route_not_found`。
