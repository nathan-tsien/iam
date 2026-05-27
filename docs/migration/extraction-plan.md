---
name: iam 初始实现：从源仓库抽取并独立化
overview: 把 源仓库/backend 中已存在的 IAM 相关代码（auth + otp + userprofile + useradmin + users repo）按 Strangler Fig 模式抽到独立的 Go 服务 iam-service，作为平台 identity-gateway 的初始实现；下游消费方 改为消费者，移除 ~6 个 auth 路由 + 7 张表的本地副本。
todos:
  - id: topology-decision
    content: Phase 0：确认两 schema 共一 Postgres、audit 走 方案 A、阶段一共享 JWT_SECRET，成文 ADR-0001
    status: pending
  - id: scaffold-iam-repo
    content: Phase 1：新建 iam-service Go module，复制 §2.1 所列验证性搬迁文件，打通 Makefile / openapi-codegen / migrate
    status: pending
  - id: trim-user-model
    content: Phase 1：从 model/User 与 repo/user 中刣除 agent_memory_paused / tier 业务字段，准备 iam-service 合并后的 baseline migration
    status: pending
  - id: iam-cmd-main
    content: Phase 1：重写 iam-service 的 cmd/api/main.go，只 wire auth/otp/userprofile/useradmin + mail + storage + ratelimit，废弃业务依赖
    status: pending
  - id: iam-openapi-slice
    content: Phase 1：从 openapi.yaml 裁出 auth + me + users 子集以及相关 schemas/responses，重跑 codegen
    status: pending
  - id: iam-internal-api
    content: Phase 1：实现 iam-service 的 /v1/internal/users/:id、batchLookup、exists 三个 HMAC 保护接口，与 webhook outbox + retry job
    status: pending
  - id: iamclient-package
    content: Phase 2：下游消费方 新建 internal/iamclient 包，HMAC 调用 + 超时重试 + LRU 缓存
    status: pending
  - id: users-local-table
    content: Phase 2：新增 0093_users_local.up.sql、新增 internal/repo/userslocal 接口（与现 repo/user 读路径签名兼容）
    status: pending
  - id: user-extensions-table
    content: Phase 2：新增 0094_user_extensions.up.sql + repo 包，读写 agent_memory_paused 全部转到该表
    status: pending
  - id: webhook-receiver
    content: Phase 2：下游消费方 接入 POST /internal/webhooks/iam（HMAC 验签 + event_id 幂等），同步 users_local
    status: pending
  - id: rewrite-callers
    content: Phase 2：全局替换 ~10 处 userrepo.FindByID / ListByIDs 调用点为 userslocal，跳 grep 验证零剧本变动
    status: pending
  - id: fo-delete-iam-modules
    content: Phase 2：下游消费方 删除 internal/service/{auth,otp,userprofile,useradmin}、repo/{refresh}、httpapi/{auth,me,me_avatar,users}、路由裁减
    status: pending
  - id: fo-license-signer-fix
    content: Phase 2：license/middleware.go 中的 admin bypass 改为 verify-only Signer（同 JWT_SECRET）
    status: pending
  - id: staging-cutover
    content: Phase 3：staging 部署 iam-service + 全量复制 public.users 到 iam.users，前端切流 auth API 到 iam-service
    status: pending
  - id: deprecate-legacy-tables
    content: Phase 3：观察 1-2 天后 drop 下游消费方 中的 users / refresh_tokens / otp_codes，成文 ADR-0002
    status: pending
  - id: billing-followup
    content: Phase 4（独立计划）：在上一份 Platform Plan 的 billing-engine 上续接，license 模块是否吸收作为 enterprise tier offline mode 留到那时决定
    status: pending
isProject: false
---


> Note: 本 plan 在 ADR-0002（multi-app & identity model）落定前撰写。ADR-0002 通过后，Phase 1 范围会扩张（per-app 用户池、sessions/login-history/self-delete 等），且 Phase 2 的"消费方改造"应迁出本仓库（属下游消费方仓库自治）。届时重写本文件。

# iam 服务初始实现：从源仓库抽取

## 1. 可行性结论 (TL;DR)

**可行，且这是一个高 ROI 的"既得现金"**。这份代码的分层是按教科书做的：
- `internal/auth/`（纯密码学，零 DB）
- `internal/repo/user/` + `internal/repo/refresh/`（GORM 仓储）
- `internal/service/auth/` + `otp/` + `userprofile/` + `useradmin/`（业务编排）
- `internal/httpapi/auth.go` + `me.go` + `users.go`（HTTP）
- 现成的 [openapi.yaml](backend/api/openapi.yaml) 8 个 `/auth/*` 路由 + 3 个 `/me*` + 5 个 `/users*` 已经 codegen 跑通

把它原地"搬"出去，比上一份 Plan 中"从零写 identity-gateway"快 **2-3 周**，质量更高（已有完整的 register/login/refresh/replay-detection/rate-limit/OTP 重发/邮件未达防枚举 等成熟特性）。

唯二的拦路点：

1. `model/User` 上挂了 2 个**业务字段** — `agent_memory_paused`、`tier`（注释说弃用但列还在）
2. 业务侧 `service/project/*` 等模块在 ~10 处直接调 `userRepo.FindByID/ListByIDs` 做 join

两个都有标准解法（见 §3）。

## 2. 当前代码盘点 (按搬迁动作分类)

下面这张清单是抽取的"路径表"，每个文件都已对照过实际内容。

### 2.1 直接搬迁 (verbatim, 改 import path 即可)

- [internal/auth/jwt.go](backend/internal/auth/jwt.go) — HS256 Signer，零 DB
- [internal/auth/password.go](backend/internal/auth/password.go) — bcrypt
- [internal/auth/passwordpolicy/policy.go](backend/internal/auth/passwordpolicy/policy.go) — 密码强度规则
- [internal/repo/refresh/refresh.go](backend/internal/repo/refresh/refresh.go) — refresh token + 旋转 + 重放检测（生产级）
- [internal/service/otp/otp.go](backend/internal/service/otp/otp.go) — OTP 发码 + 防并发竞态注释完整
- [internal/service/auth/auth.go](backend/internal/service/auth/auth.go) — Register/Login/Refresh/Logout/CheckAvailability
- [internal/service/auth/password_reset.go](backend/internal/service/auth/password_reset.go) — ForgotPassword/ResetPassword
- [internal/service/userprofile/userprofile.go](backend/internal/service/userprofile/userprofile.go) — display_name + avatar 自助编辑
- [internal/service/useradmin/useradmin.go](backend/internal/service/useradmin/useradmin.go) + [actions.go](backend/internal/service/useradmin/actions.go) — admin disable/enable/trigger-reset
- [internal/middleware/auth.go](backend/internal/middleware/auth.go) + [rbac.go](backend/internal/middleware/rbac.go) — gin bearer + role gate
- [internal/provider/mail/*](backend/internal/provider/mail) — SMTP + LogMailer
- [internal/ratelimit/*](backend/internal/ratelimit) — Redis bucket + memory fallback
- [internal/httpapi/auth.go](backend/internal/httpapi/auth.go) — 8 个 auth handler
- [internal/httpapi/me.go](backend/internal/httpapi/me.go) + [me_avatar.go](backend/internal/httpapi/me_avatar.go)
- [internal/httpapi/users.go](backend/internal/httpapi/users.go) — admin user 管理
- 迁移文件：`migrations/0002_users.up.sql`, `0003_refresh_tokens.up.sql`, `0004_otp_codes.up.sql`, `0013_users_display_name.*`, `0014_users_email_lower_prefix.*`, `0015_users_disabled_at.*`, `0020_users_avatar_url.*`
- OpenAPI 切片：openapi.yaml 行 78-280（auth）+ 280-450（me）+ 1761-1900（users）

### 2.2 剥离后搬迁 (需要小手术)

- [internal/model/user.go](backend/internal/model/user.go) — **删** `tier` 引用相关位（schema 0002 的 `tier` 列+CHECK）、**移走** `agent_memory_paused` 到 下游消费方 自己的 `user_extensions` 表
- [internal/repo/user/user.go](backend/internal/repo/user/user.go) — 删除 `IsAgentMemoryPaused` / `SetAgentMemoryPaused` 两个方法（行 366-394）
- [internal/config/config.go](backend/internal/config/config.go) — 拆成 iam-service 的 `Config`（保留 JWT/Refresh/Mail/Rate/DevOTPCode/Storage-for-avatars） 和 下游消费方 剩下的部分
- [cmd/api/main.go](backend/cmd/api/main.go) — 切两份，iam-service 的 main 只保留 auth+otp+userprofile+useradmin 的 wiring

### 2.3 留在 下游消费方 (业务相关)

- [internal/license/](backend/internal/license) — 这是**部署级 license**（HMAC 签名 token，offline，按 org 计），跟"per-user 订阅"不是同一个东西；阶段二跟随 billing-engine 单独再处理
- `internal/middleware/hmac.go` — agent-gateway 到本服务的 HMAC，IAM 用不到
- `service/project/*`, `service/agentchat/*`, `service/agentmemory/*`, `service/skillsvc/*` 全部留下
- `repo/audit/*` — audit log 是 下游消费方 的业务日志（包含 project、skill 的审计），不属于 IAM；useradmin 搬迁后 audit 写入改为发 webhook 或异步 message 到 下游消费方（见 §4.4）
- `migrations/0021+` 全部留下

### 2.4 需要重写的部分

- `iamclient/` — 下游消费方 新建的 IAM HTTP 客户端 + 本地 `users_local` 缓存表（见 §4.2）
- `iam-service` 的 internal-API：`POST /v1/internal/verify-token`（可选，下游直接 verify JWT 也行）和 `GET /v1/internal/users/:id` + `GET /v1/internal/users:batchLookup`，HMAC 保护

## 3. 三处关键耦合 + 拆法

### 3.1 `users.agent_memory_paused` (业务字段挂在 IAM 模型上)

事实：[user.go L370-394](backend/internal/repo/user/user.go) + [service/agentmemory/service.go L341](backend/internal/service/agentmemory/service.go) 直接读写 `users` 表的 `agent_memory_paused` 列。

拆法：

- 新建 下游消费方 迁移 `0093_user_extensions.up.sql`:

```sql
CREATE TABLE user_extensions (
  user_id              UUID PRIMARY KEY,
  agent_memory_paused  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- `agentmemorysvc` 改为依赖一个新 `userext.Repo`，方法签名不变
- 数据迁移：`INSERT INTO user_extensions(user_id, agent_memory_paused) SELECT id, agent_memory_paused FROM users WHERE agent_memory_paused IS NOT NULL;`
- 然后 `ALTER TABLE users DROP COLUMN agent_memory_paused;`（这条 migration 在 iam-service 仓库执行）

### 3.2 `users.tier` (注释已弃用但列仍在)

事实：[migrations/0002_users.up.sql](backend/migrations/0002_users.up.sql) 仍有 `tier TEXT NOT NULL DEFAULT 'normal' CHECK (...)`；代码注释（[model/user.go L21](backend/internal/model/user.go)）说应用层已不读它。

拆法：直接在 iam-service 的初始 baseline migration 中省略该列，无须处理代码。

### 3.3 下游模块的 `userRepo.FindByID/ListByIDs`

事实（已用 grep 确认）：

- [service/project/project.go](backend/internal/service/project/project.go) L189: `s.Users.FindByID(ctx, in.OwnerUserID)`
- [service/project/members.go](backend/internal/service/project/members.go) L53
- [service/project/invite.go](backend/internal/service/project/invite.go) L101
- [service/project/files.go](backend/internal/service/project/files.go) L339
- [service/agentmemory/service.go](backend/internal/service/agentmemory/service.go) L341/368/373

拆法 — **本地缓存表 + webhook 同步**（行业标准做法，避免 N+1 HTTP）：

```sql
CREATE TABLE users_local (
  id            UUID PRIMARY KEY,
  email         TEXT NOT NULL,
  display_name  TEXT,
  role          TEXT NOT NULL,
  disabled_at   TIMESTAMPTZ,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  synced_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_local_email ON users_local (LOWER(email));
```

- iam-service 在 `user.created/updated/disabled/enabled` 时发 webhook 到 下游消费方 的 `/internal/webhooks/iam`（HMAC 签名）
- 下游消费方 维护 `users_local`，**所有 `userRepo.FindByID` 替换为 `usersLocalRepo.FindByID`**，**接口签名不变**
- 启动时做一次全量回填（`GET /v1/internal/users?cursor=...`）
- 一致性：webhook 失败时 retry-with-DLQ；额外跑一个 5min 的对账 job

## 4. 提议架构

### 4.1 仓库与 DB 拓扑

- 新仓库：`iam-service`（Go module: `github.com/<you>/iam-service`）
- DB：阶段一**两 schema 共用一个 Postgres**（`iam.*` 给 iam-service，`public.*` 留给 下游消费方），跨 schema 用 FK 不可能但**应用层完全够用**；阶段二再拆独立 DB
- 部署：docker-compose 同时起 `iam-service:8090` + `consumer-app-api:8080` + `postgres` + `redis`，CI 跑端到端 smoke
- 配置：阶段一两服务**共用同一个 `JWT_SECRET`** → 下游消费方 用 IAM 颁发的 JWT 时本地 verify，零 RPC

### 4.2 iam-service 的对外 API

公共面（基本照搬现有 openapi.yaml 切片）：

- `POST /v1/auth/register` / `check-availability` / `otp/verify` / `login` / `refresh` / `logout` / `password/forgot` / `password/reset`
- `GET /v1/me` / `PATCH /v1/me`
- `POST /v1/me/avatar/presign` / `commit`
- `GET /v1/users` (admin) / `GET /v1/users/search` / `POST /v1/users/{id}/disable|enable|password-reset`

内部面（HMAC 签名，供 下游消费方 等下游消费）：

- `POST /v1/internal/verify-token` — 可选；下游直接 local verify 即可
- `GET /v1/internal/users/{id}` — 单查
- `POST /v1/internal/users:batchLookup` — `{ ids: [...] }` 批查（取代 `ListByIDs`）
- `POST /v1/internal/users:exists` — 取代 `FindByID` 的 "存在性检查" 场景
- 下游订阅 webhook：iam-service 推 `user.created` / `user.updated` / `user.disabled` / `user.enabled` 事件，签名 HMAC

### 4.3 下游消费方 端的改造

- 新建 `internal/iamclient/`（HMAC 客户端 + 重试）
- 新建 `internal/repo/userslocal/`（结构跟 `repo/user/` 镜像但只读 + 由 webhook 写入）
- 用 sed-style 全局替换：把 `userrepo.Repo` 的所有 read 调用替换为 `userslocal.Repo` 的同名方法（**接口签名保持兼容**是关键，把 `internal/repo/user/` 改成 alias 包过渡期）
- 删除路由：把 router.go 里的 `/api/v1/auth/*`、`/api/v1/me`、`/api/v1/me/avatar/*`、`/api/v1/users*` 删掉
- middleware：`internal/middleware/auth.go` 仅依赖 `auth.Signer.Verify`，**保留**；JWT_SECRET 共享，token 验证逻辑不动
- `internal/middleware/rbac.go` 同上保留
- `useradmin` 整块删除（下游消费方 不再做用户管理；admin 操作改为登录 iam-service 的 admin 面板）— 但 **audit log 写入** 需要保留（见 §4.4）

### 4.4 Audit log 跨边界

事实：[useradmin/actions.go](backend/internal/service/useradmin/actions.go) 在同一事务里 `users.disabled_at flip + refresh.revoke + audit.insert`，audit 表在 下游消费方 业务侧。

两种处理路径，按需要选：

- **方案 A（推荐 MVP）**：把 audit 同样搬到 iam-service（新建 `iam.audit_logs` 表，schema 同当前 `audit_logs`），下游消费方 自己的业务 audit 留下不动。理由：管 user 的事就让 IAM 写自己的 audit，没必要跨边界事务
- **方案 B**：iam-service 把 audit 用事件流（NATS / Postgres LISTEN/NOTIFY）发给 下游消费方 异步写入，最终一致 — 工程更重，没必要

→ 选 **A**。

### 4.5 与上一份 Platform Plan 的关系

直接对接。Platform Plan 中：

```
platform/services/identity-gateway/    ← 就是这次抽出的 iam-service
platform/services/billing-engine/      ← 留给后续
platform/services/profile-service/     ← 这次抽出后 IAM 已自带 profile，不再单独立服务
```

修正：上一份 Plan 我把 profile 单独立服务，但**现有代码 profile 就长在 IAM 里**（`userprofile/`），不必拆。`services/profile-service/` 折叠回 `identity-gateway/`，等真有跨产品的 prefs 时再拆。

Provider Adapter 演进路径（Platform Plan §4 中描述）：
- 当前抽出的 IAM 默认 `LocalProvider`（email + 密码 + OTP，自管 Postgres）
- 后续在 `internal/identityprovider/` 里加 `ClerkProvider`、`AuthingProvider`、`WechatOAuthProvider`，与 LocalProvider 并列
- Register/Login 路径变成多 provider 路由

## 5. 分阶段实施（含工作量估算）

### Phase 0 (0.5 天)：拓扑决策

- 确认是否接受"两 schema 共用一个 Postgres"
- 确认 audit 走方案 A
- 确认是否暂保留共享 JWT_SECRET（同一 token 兼容）
- 写下 ADR-0001（IAM 抽取决策）

### Phase 1 (2-3 天)：carve out iam-service 仓库

- 新建 `iam-service` Go module
- 按 §2.1 复制文件，改 import path（`github.com/nathan-tsien/源仓库/internal/...` → `github.com/<you>/iam-service/internal/...`）
- 按 §2.2 做小手术（删 `tier`/`agent_memory_paused`）
- 写新的 `cmd/api/main.go`：只 wire auth/otp/userprofile/useradmin + mail + storage + ratelimit
- 写 `migrations/`：baseline = 0002+0003+0004+0013+0014+0015+0020 的合并 + drop 业务字段
- 单元测试全部跟着搬（auth_test.go / otp_test.go / userprofile_test.go / useradmin_test.go / refresh_test.go / user_test.go）+ httpapi 集成测试
- 改 openapi.yaml 只保留 auth + me + users 部分；codegen 验证
- iam-service `make test` 全绿后才进入 Phase 2

### Phase 2 (2-3 天)：下游消费方 改造为消费者

- 新建 `internal/iamclient/`
- 新建 `internal/repo/userslocal/`（接口与 `internal/repo/user/` 兼容）+ `migrations/0093_users_local.up.sql`、`0094_user_extensions.up.sql`
- 写 `/internal/webhooks/iam` 接收端，HMAC 验签后更新 `users_local`
- 实现回填脚本：从 iam-service 全量拉一次写 `users_local`
- 把 `service/project/*` 等 ~10 处 `s.Users.X` 改为新 client（接口签名兼容则 0 调用方代码改动，只换注入）
- 改 `service/agentmemory/service.go`：`IsAgentMemoryPaused/SetAgentMemoryPaused` 改读 `user_extensions`
- 删 下游消费方 的 `internal/service/auth/`、`otp/`、`userprofile/`、`useradmin/`、`repo/refresh/`、`httpapi/auth.go`、`me.go`、`me_avatar.go`、`users.go`、`me_agent_memory.go`（部分）
- router 删 `/auth/*`、`/me`、`/me/avatar/*`、`/users*` 路由
- `cmd/api/main.go` 精简：去掉 authSvc/otpSvc/userprofileSvc/userAdminSvc 的 wiring
- 老的 `users` `refresh_tokens` `otp_codes` 表**先不 drop**（同 DB 同 schema，留 read-only 兜底），等观察期过再删

### Phase 3 (1 天)：数据切流 + 切断

- 部署 iam-service 到 staging，连同 下游消费方 staging
- 写一次性数据迁移：`INSERT INTO iam.users SELECT id, email, ... FROM public.users;`（同 Postgres 跨 schema 复制秒级完成）
- 切流：把前端的 `/api/v1/auth/*` 调用指向 iam-service 域名
- 共享 JWT_SECRET 期间，token 可以由 iam-service 颁发、下游消费方 本地 verify，零中断
- 观察 1-2 天 → drop 下游消费方 中的旧 `users`/`refresh_tokens`/`otp_codes` 表
- 写 ADR-0002（下游消费方 边界后置态）

### Phase 4 (异步)：上一份 Plan 的 billing-engine

不在本次抽取范围。`internal/license/` 留在 下游消费方 不动；billing-engine 上线后再决定是否吸收 license 的 HMAC-token offline 模式作为 enterprise tier 的一种。

## 6. 风险与缓解

- **共享 JWT_SECRET**：阶段一接受；阶段二把 iam-service 升级为 RS256 + JWKS endpoint，下游消费方 改 verify 路径，secret 不再共享
- **跨 schema 失去 FK**：`project_members.user_id` 不再硬约束 `users(id)`；缓解：webhook 一致性 + 5min 对账 job + 业务侧 `users_local` 兜底
- **webhook 抖动**：iam-service 用 outbox 表 + retry job 保 at-least-once；下游消费方 接收幂等（按 `event_id` 去重）
- **同名包**：`internal/auth/` 在两个仓库都存在，import path 改了不会冲突；下游消费方 留下的 `auth.Signer` 只做 verify
- **avatar 走的对象存储**：iam-service 自己持有 STORAGE_* 凭证（同一 bucket 不同前缀 `iam/avatars/`），不和 下游消费方 共享 IAM 角色
- **OTP rate-limit**：现有按 email 限流的 redis bucket key 不需变；iam-service 自己持有 Redis 连接
- **license-middleware 失去 signer**：[license/middleware.go L25](backend/internal/license/middleware.go) 通过 signer 解析 token 拿 role 做 admin bypass；下游消费方 删除 signer 后改为 verify-only Signer（共享 secret 期），后续切 JWKS 同步
- **下游 `userRepo.UpdateProfile` 等写路径**：抽走后 下游消费方 **不再有 user 写权限**；任何业务代码尝试写 `users.X` 都要改为调 iam-service API 或直接禁止；grep `UpdateProfile|UpdateAvatarStorageKey|UpdatePassword|UpdateRegistration|SetEmailVerified` 已确认只在 IAM 自己模块调用，安全

## 7. 不做的事 (划清边界)

- 不重写为 Node/TS。现成的 Go 代码质量很高（看 [refresh.go Rotate](backend/internal/repo/refresh/refresh.go) 的 replay-detection、[otp.go Issue](backend/internal/service/otp/otp.go) 的事务+邮件顺序设计），重写浪费 2-3 周
- 不在本次引入 Clerk/Authing/Wechat。LocalProvider 先跑起来，下一轮在 `internal/identityprovider/` 里加适配器
- 不引入 multi-tenant claims（`tenantId`/`region`）。当前 JWT claim 是 `{sub, role}`，足够 下游消费方；未来加 `tenant_id` 是非破坏性的（jwt-go 忽略未知字段，旧 token 兼容）
- 不动 下游消费方 的 `audit_logs` 业务表
- 不引入 OIDC discovery / OAuth2 server。LocalProvider 是 email+password+OTP，下游用对称 HMAC verify token 即可

## 8. 抽取后的结构示意

```mermaid
flowchart LR
  subgraph iam [iam-service 8090]
    iamAuth["auth handlers<br/>/v1/auth/*"]
    iamMe["/v1/me /v1/me/avatar"]
    iamUsers["/v1/users (admin)"]
    iamInternal["/v1/internal/* HMAC"]
    iamRepo[(iam schema:<br/>users, refresh_tokens,<br/>otp_codes, audit_logs)]
  end

  subgraph fo [consumer-app-api 8080]
    foRoutes["project skill notification<br/>agent chat ..."]
    foMW["middleware.Auth<br/>verify-only Signer"]
    foLocal[(public schema:<br/>users_local, user_extensions,<br/>projects, skills ...)]
    foClient["iamclient<br/>+ webhook handler"]
  end

  browser[Web/App] -->|"POST /v1/auth/login"| iamAuth
  browser -->|"GET /api/v1/projects (Bearer JWT)"| foMW
  foMW --> foRoutes
  foRoutes --> foLocal
  foRoutes -.cold lookup.-> foClient
  foClient -->|"batchLookup HMAC"| iamInternal
  iamInternal --> iamRepo
  iamAuth --> iamRepo
  iam -.user.created/updated webhook.-> foClient
  foClient --> foLocal
```

## 9. 验收信号

- iam-service 启动后，所有 [openapi.yaml](backend/api/openapi.yaml) 中 auth/me/users 切片的端到端测试用例通过（直接搬现有 [auth_test.go](backend/internal/httpapi/auth_test.go)、[me_test.go](backend/internal/httpapi/me_test.go)、[users_test.go](backend/internal/httpapi/users_test.go)）
- 下游消费方 删除 ~12 个文件 + ~4 张表后 `go test ./...` 全绿
- 端到端流程通过：浏览器在 iam-service 上注册→登录→拿 token→访问 下游消费方 的 `/api/v1/projects` 仍可正常工作
- iam-service 的 webhook 在 user.created 时 下游消费方 `users_local` 在 1s 内出现新行
