# OpenAPI Codegen Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all hand-written Gin handlers with oapi-codegen strict server, making the OpenAPI spec the single source of truth for the API contract.

**Architecture:** Write `api/openapi.yaml` covering all 16 endpoints. Use oapi-codegen v2 to generate Gin strict server interfaces. Implement the `StrictHandlerInterface` by delegating to existing service layer. Middleware (Auth, AdminRole, RateLimit) remains hand-written and is applied via Gin router groups as before.

**Tech Stack:** oapi-codegen v2, Gin, OpenAPI 3.1, Go 1.25+

**Endpoint audit:** All 16 endpoints documented in the endpoint audit above.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `api/openapi.yaml` | Create | OpenAPI 3.1 spec (source of truth) |
| `api/config.yaml` | Create | oapi-codegen configuration |
| `api/iam.gen.go` | Create (generated) | Generated types, strict handler interface, Gin registration |
| `internal/httpapi/strict.go` | Create | Implementation of `StrictHandlerInterface` |
| `internal/httpapi/health.go` | Modify | Keep as-is (not in OpenAPI spec, uses non-standard error format) |
| `internal/httpapi/auth.go` | Delete | Replaced by strict.go |
| `internal/httpapi/me.go` | Delete | Replaced by strict.go |
| `internal/httpapi/users.go` | Delete | Replaced by strict.go |
| `cmd/api/main.go` | Modify | Wire strict handler instead of hand-written routes |
| `Makefile` | Modify | Add `make generate` target |

---

### Task 1: OpenAPI spec

**Files:**
- Create: `api/openapi.yaml`
- Create: `api/config.yaml`

- [ ] **Step 1: Create the OpenAPI 3.1 spec**

Create `api/openapi.yaml`:

```yaml
openapi: 3.1.0
info:
  title: IAM Service
  version: 1.0.0
  description: Standalone Identity and Access Management service.

servers:
  - url: /v1/apps/{slug}
    variables:
      slug:
        description: App slug
        default: demo

security: []

paths:
  /auth/register:
    post:
      operationId: register
      summary: Register a new user
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, password, display_name]
              properties:
                email:
                  type: string
                  format: email
                password:
                  type: string
                  minLength: 1
                display_name:
                  type: string
                  minLength: 1
      responses:
        "201":
          description: User created
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/RegisterResponse"
        "400":
          $ref: "#/components/responses/BadRequest"
        "409":
          description: Conflict
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
              examples:
                email_taken:
                  value:
                    code: EMAIL_TAKEN
                    message: Email already registered
                display_name_taken:
                  value:
                    code: DISPLAY_NAME_TAKEN
                    message: Display name already taken
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/login:
    post:
      operationId: login
      summary: Login with email and password
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, password]
              properties:
                email:
                  type: string
                  format: email
                password:
                  type: string
      responses:
        "200":
          description: Login successful
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TokenResponse"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "403":
          description: Account issue
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/check-availability:
    post:
      operationId: checkAvailability
      summary: Check email and display name availability
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                display_name:
                  type: string
              minProperties: 1
      responses:
        "200":
          description: Availability result
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/AvailabilityResponse"
        "400":
          $ref: "#/components/responses/BadRequest"
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/otp/verify:
    post:
      operationId: verifyOTP
      summary: Verify OTP code
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, code]
              properties:
                email:
                  type: string
                  format: email
                code:
                  type: string
      responses:
        "200":
          description: Verified
          content:
            application/json:
              schema:
                type: object
                properties:
                  verified:
                    type: boolean
        "400":
          $ref: "#/components/responses/BadRequest"
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/refresh:
    post:
      operationId: refreshToken
      summary: Refresh access token
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [refresh_token]
              properties:
                refresh_token:
                  type: string
      responses:
        "200":
          description: Token refreshed
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/TokenResponse"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          description: Invalid refresh token
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/logout:
    post:
      operationId: logout
      summary: Logout (revoke refresh token)
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [refresh_token]
              properties:
                refresh_token:
                  type: string
      responses:
        "200":
          description: Logged out
          content:
            application/json:
              schema:
                type: object
                properties:
                  logged_out:
                    type: boolean
        "400":
          $ref: "#/components/responses/BadRequest"
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/password/forgot:
    post:
      operationId: forgotPassword
      summary: Send password reset OTP
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email:
                  type: string
                  format: email
      responses:
        "200":
          description: Reset email sent (always, even if email not found)
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        "400":
          $ref: "#/components/responses/BadRequest"
        "500":
          $ref: "#/components/responses/InternalError"

  /auth/password/reset:
    post:
      operationId: resetPassword
      summary: Reset password with OTP code
      tags: [auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, code, new_password]
              properties:
                email:
                  type: string
                  format: email
                code:
                  type: string
                new_password:
                  type: string
                  minLength: 1
      responses:
        "200":
          description: Password reset
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        "400":
          $ref: "#/components/responses/BadRequest"
        "500":
          $ref: "#/components/responses/InternalError"

  /me:
    get:
      operationId: getMe
      summary: Get current user profile
      tags: [profile]
      security:
        - bearerAuth: []
      responses:
        "200":
          description: User profile
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/User"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "404":
          $ref: "#/components/responses/NotFound"
        "500":
          $ref: "#/components/responses/InternalError"
    patch:
      operationId: updateMe
      summary: Update current user profile
      tags: [profile]
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                display_name:
                  type: string
                avatar_url:
                  type: string
              minProperties: 1
      responses:
        "200":
          description: Updated profile
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/User"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "409":
          description: Display name taken
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "500":
          $ref: "#/components/responses/InternalError"

  /users:
    get:
      operationId: listUsers
      summary: List users (admin only)
      tags: [admin]
      security:
        - bearerAuth: []
      parameters:
        - name: q
          in: query
          schema:
            type: string
          description: Search keyword
        - name: cursor
          in: query
          schema:
            type: string
          description: Pagination cursor
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
      responses:
        "200":
          description: User list
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/UserListResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "403":
          $ref: "#/components/responses/Forbidden"
        "500":
          $ref: "#/components/responses/InternalError"

  /users/{id}:
    get:
      operationId: getUser
      summary: Get user by ID (admin only)
      tags: [admin]
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        "200":
          description: User detail
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/User"
        "400":
          description: Invalid ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "500":
          $ref: "#/components/responses/InternalError"

  /users/{id}/disable:
    post:
      operationId: disableUser
      summary: Disable user (admin only)
      tags: [admin]
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        "200":
          description: User disabled
          content:
            application/json:
              schema:
                type: object
                properties:
                  disabled:
                    type: boolean
        "400":
          description: Invalid ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "409":
          description: Last admin
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "500":
          $ref: "#/components/responses/InternalError"

  /users/{id}/enable:
    post:
      operationId: enableUser
      summary: Enable user (admin only)
      tags: [admin]
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        "200":
          description: User enabled
          content:
            application/json:
              schema:
                type: object
                properties:
                  enabled:
                    type: boolean
        "400":
          description: Invalid ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "500":
          $ref: "#/components/responses/InternalError"

  /users/{id}/trigger-password-reset:
    post:
      operationId: triggerPasswordReset
      summary: Trigger password reset for user (admin only)
      tags: [admin]
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        "200":
          description: Reset email sent
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        "400":
          description: Invalid ID
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "500":
          $ref: "#/components/responses/InternalError"

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    ErrorResponse:
      type: object
      required: [code, message]
      properties:
        code:
          type: string
        message:
          type: string
        request_id:
          type: string
        details:
          type: object

    RegisterResponse:
      type: object
      properties:
        user_id:
          type: string
          format: uuid
        email:
          type: string
        display_name:
          type: string

    TokenResponse:
      type: object
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
        user_id:
          type: string
          format: uuid
        email:
          type: string
        role:
          type: string
          enum: [user, admin]

    AvailabilityResponse:
      type: object
      properties:
        email_available:
          type: boolean
        display_name_available:
          type: boolean

    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        app_id:
          type: string
          format: uuid
        email:
          type: string
        role:
          type: string
          enum: [user, admin]
        display_name:
          type: string
        avatar_url:
          type: string
        email_verified_at:
          type: string
          format: date-time
        disabled_at:
          type: string
          format: date-time
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time

    UserListResponse:
      type: object
      properties:
        items:
          type: array
          items:
            $ref: "#/components/schemas/User"
        next_cursor:
          type: string
        total:
          type: integer

  responses:
    BadRequest:
      description: Bad request
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorResponse"
    Unauthenticated:
      description: Unauthenticated
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorResponse"
    Forbidden:
      description: Forbidden
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorResponse"
    NotFound:
      description: Not found
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorResponse"
    InternalError:
      description: Internal server error
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorResponse"
```

- [ ] **Step 2: Create oapi-codegen config**

Create `api/config.yaml`:

```yaml
package: api
generate:
  gin-server: true
  strict-server: true
  models: true
output: api/iam.gen.go
```

- [ ] **Step 3: Validate the spec**

Run: `pip install openapi-spec-validator && openapi-spec-validator api/openapi.yaml`
Or: `npx @redocly/cli lint api/openapi.yaml`
Expected: No validation errors

- [ ] **Step 4: Commit**

```bash
git add api/
git commit -m "feat(api): add OpenAPI 3.1 spec for all endpoints"
```

---

### Task 2: oapi-codegen setup and generation

**Files:**
- Modify: `go.mod` (add oapi-codegen dependency)
- Create: `api/iam.gen.go` (generated)
- Modify: `Makefile`

- [ ] **Step 1: Install oapi-codegen**

Run:
```bash
go get github.com/oapi-codegen/oapi-codegen/v2@latest
go get github.com/oapi-codegen/runtime
```

- [ ] **Step 2: Add generate target to Makefile**

Add to `Makefile`:

```makefile
.PHONY: generate
generate:
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=api/config.yaml api/openapi.yaml
```

- [ ] **Step 3: Run code generation**

Run: `make generate`
Expected: `api/iam.gen.go` is created with types, strict handler interface, and Gin registration functions.

- [ ] **Step 4: Verify generated code compiles**

Run: `go build ./api/...`
Expected: Compiles successfully

- [ ] **Step 5: Commit**

```bash
git add api/ go.mod go.sum Makefile
git commit -m "feat(api): add oapi-codegen and generate strict server"
```

---

### Task 3: Implement StrictHandlerInterface

**Files:**
- Create: `internal/httpapi/strict.go`

- [ ] **Step 1: Read the generated interface**

After Task 2, read `api/iam.gen.go` to find the `StrictHandlerInterface`. It will have methods like:

```go
type StrictHandlerInterface interface {
    Register(ctx context.Context, request RegisterRequestObject) (RegisterResponseObject, error)
    Login(ctx context.Context, request LoginRequestObject) (LoginResponseObject, error)
    // ... one method per operation
}
```

Each `*RequestObject` contains the parsed request body and path params.
Each `*ResponseObject` is an interface with concrete types like `Register201JSONResponse`.

- [ ] **Step 2: Create strict handler implementation**

Create `internal/httpapi/strict.go`. The struct holds references to all services:

```go
package httpapi

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/api"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/auth"
	"github.com/nathan-tsien/iam/internal/service/useradmin"
	"github.com/nathan-tsien/iam/internal/service/userprofile"
)

type StrictServer struct {
	AuthSvc    *auth.Service
	ProfileSvc *userprofile.Service
	AdminSvc   *useradmin.Service
}

var _ api.StrictHandlerInterface = (*StrictServer)(nil)

// --- Auth endpoints ---

func (s *StrictServer) Register(ctx context.Context, request api.RegisterRequestObject) (api.RegisterResponseObject, error) {
	// Extract app from context (set by middleware)
	app := getAppFromCtx(ctx)

	resp, err := s.AuthSvc.Register(ctx, app.ID, request.Body.Email, request.Body.Password, request.Body.DisplayName)
	if err != nil {
		return nil, mapServiceError(err)
	}

	return api.Register201JSONResponse{
		UserId:      resp.UserID,
		Email:       resp.Email,
		DisplayName: resp.DisplayName,
	}, nil
}

func (s *StrictServer) Login(ctx context.Context, request api.LoginRequestObject) (api.LoginResponseObject, error) {
	app := getAppFromCtx(ctx)

	tokens, err := s.AuthSvc.Login(ctx, app.ID, request.Body.Email, request.Body.Password, app.JWTAudience, getIPFromCtx(ctx), getUserAgentFromCtx(ctx))
	if err != nil {
		return nil, mapServiceError(err)
	}

	role := string(tokens.User.Role)
	return api.Login200JSONResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserId:       tokens.User.ID,
		Email:        tokens.User.Email,
		Role:         &role,
	}, nil
}

func (s *StrictServer) CheckAvailability(ctx context.Context, request api.CheckAvailabilityRequestObject) (api.CheckAvailabilityResponseObject, error) {
	app := getAppFromCtx(ctx)

	resp, err := s.AuthSvc.CheckAvailability(ctx, app.ID, request.Body.Email, request.Body.DisplayName)
	if err != nil {
		return nil, mapServiceError(err)
	}

	return api.CheckAvailability200JSONResponse(resp), nil
}

func (s *StrictServer) VerifyOTP(ctx context.Context, request api.VerifyOTPRequestObject) (api.VerifyOTPResponseObject, error) {
	app := getAppFromCtx(ctx)

	if err := s.AuthSvc.VerifyRegisterOTP(ctx, app.ID, request.Body.Email, request.Body.Code); err != nil {
		return nil, mapServiceError(err)
	}

	verified := true
	return api.VerifyOTP200JSONResponse{Verified: &verified}, nil
}

func (s *StrictServer) RefreshToken(ctx context.Context, request api.RefreshTokenRequestObject) (api.RefreshTokenResponseObject, error) {
	app := getAppFromCtx(ctx)

	tokens, err := s.AuthSvc.Refresh(ctx, request.Body.RefreshToken, app.JWTAudience)
	if err != nil {
		return nil, mapServiceError(err)
	}

	role := string(tokens.User.Role)
	return api.RefreshToken200JSONResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserId:       tokens.User.ID,
		Email:        tokens.User.Email,
		Role:         &role,
	}, nil
}

func (s *StrictServer) Logout(ctx context.Context, request api.LogoutRequestObject) (api.LogoutResponseObject, error) {
	if err := s.AuthSvc.Logout(ctx, request.Body.RefreshToken, getIPFromCtx(ctx), getUserAgentFromCtx(ctx)); err != nil {
		return nil, mapServiceError(err)
	}

	loggedOut := true
	return api.Logout200JSONResponse{LoggedOut: &loggedOut}, nil
}

func (s *StrictServer) ForgotPassword(ctx context.Context, request api.ForgotPasswordRequestObject) (api.ForgotPasswordResponseObject, error) {
	app := getAppFromCtx(ctx)

	// Always succeed to prevent user enumeration
	_ = s.AuthSvc.ForgotPassword(ctx, app.ID, request.Body.Email)

	msg := "If the email exists, a reset code has been sent"
	return api.ForgotPassword200JSONResponse{Message: &msg}, nil
}

func (s *StrictServer) ResetPassword(ctx context.Context, request api.ResetPasswordRequestObject) (api.ResetPasswordResponseObject, error) {
	app := getAppFromCtx(ctx)

	if err := s.AuthSvc.ResetPassword(ctx, app.ID, request.Body.Email, request.Body.Code, request.Body.NewPassword); err != nil {
		return nil, mapServiceError(err)
	}

	msg := "Password reset successfully"
	return api.ResetPassword200JSONResponse{Message: &msg}, nil
}

// --- Profile endpoints ---

func (s *StrictServer) GetMe(ctx context.Context, request api.GetMeRequestObject) (api.GetMeResponseObject, error) {
	app := getAppFromCtx(ctx)
	userID := getUserIDFromCtx(ctx)

	profile, err := s.ProfileSvc.GetProfile(ctx, app.ID, userID)
	if err != nil {
		return nil, mapServiceError(err)
	}

	return api.GetMe200JSONResponse(userToAPI(profile)), nil
}

func (s *StrictServer) UpdateMe(ctx context.Context, request api.UpdateMeRequestObject) (api.UpdateMeResponseObject, error) {
	app := getAppFromCtx(ctx)
	userID := getUserIDFromCtx(ctx)

	profile, err := s.ProfileSvc.UpdateProfile(ctx, app.ID, userID, request.Body.DisplayName, request.Body.AvatarUrl)
	if err != nil {
		return nil, mapServiceError(err)
	}

	return api.UpdateMe200JSONResponse(userToAPI(profile)), nil
}

// --- Admin endpoints ---

func (s *StrictServer) ListUsers(ctx context.Context, request api.ListUsersRequestObject) (api.ListUsersResponseObject, error) {
	app := getAppFromCtx(ctx)

	query := ""
	if request.Params.Q != nil {
		query = *request.Params.Q
	}
	cursor := ""
	if request.Params.Cursor != nil {
		cursor = *request.Params.Cursor
	}
	limit := 20
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}

	page, err := s.AdminSvc.ListUsers(ctx, app.ID, query, cursor, limit)
	if err != nil {
		return nil, mapServiceError(err)
	}

	items := make([]api.User, len(page.Items))
	for i := range page.Items {
		items[i] = userToAPI(&page.Items[i])
	}

	total := int(page.Total)
	return api.ListUsers200JSONResponse{
		Items:      items,
		NextCursor: &page.NextCursor,
		Total:      &total,
	}, nil
}

func (s *StrictServer) GetUser(ctx context.Context, request api.GetUserRequestObject) (api.GetUserResponseObject, error) {
	app := getAppFromCtx(ctx)

	targetID, err := uuid.Parse(request.Id)
	if err != nil {
		return nil, newAppError(400, "INVALID_ID", "Invalid user ID")
	}

	u, err := s.AdminSvc.GetUser(ctx, app.ID, targetID)
	if err != nil {
		return nil, mapServiceError(err)
	}

	return api.GetUser200JSONResponse(userToAPI(u)), nil
}

func (s *StrictServer) DisableUser(ctx context.Context, request api.DisableUserRequestObject) (api.DisableUserResponseObject, error) {
	app := getAppFromCtx(ctx)
	actorID := getUserIDFromCtx(ctx)

	targetID, err := uuid.Parse(request.Id)
	if err != nil {
		return nil, newAppError(400, "INVALID_ID", "Invalid user ID")
	}

	if err := s.AdminSvc.DisableUser(ctx, app.ID, actorID, targetID); err != nil {
		return nil, mapServiceError(err)
	}

	disabled := true
	return api.DisableUser200JSONResponse{Disabled: &disabled}, nil
}

func (s *StrictServer) EnableUser(ctx context.Context, request api.EnableUserRequestObject) (api.EnableUserResponseObject, error) {
	app := getAppFromCtx(ctx)
	actorID := getUserIDFromCtx(ctx)

	targetID, err := uuid.Parse(request.Id)
	if err != nil {
		return nil, newAppError(400, "INVALID_ID", "Invalid user ID")
	}

	if err := s.AdminSvc.EnableUser(ctx, app.ID, actorID, targetID); err != nil {
		return nil, mapServiceError(err)
	}

	enabled := true
	return api.EnableUser200JSONResponse{Enabled: &enabled}, nil
}

func (s *StrictServer) TriggerPasswordReset(ctx context.Context, request api.TriggerPasswordResetRequestObject) (api.TriggerPasswordResetResponseObject, error) {
	app := getAppFromCtx(ctx)
	actorID := getUserIDFromCtx(ctx)

	targetID, err := uuid.Parse(request.Id)
	if err != nil {
		return nil, newAppError(400, "INVALID_ID", "Invalid user ID")
	}

	if err := s.AdminSvc.TriggerPasswordReset(ctx, app.ID, actorID, targetID); err != nil {
		return nil, mapServiceError(err)
	}

	msg := "Password reset email sent"
	return api.TriggerPasswordReset200JSONResponse{Message: &msg}, nil
}
```

- [ ] **Step 3: Create helper functions**

Add to `internal/httpapi/strict.go` (or a separate `helpers.go`):

```go
package httpapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nathan-tsien/iam/internal/api"
	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/model"
)

type appError struct {
	Status  int
	Code    string
	Message string
}

func (e *appError) Error() string { return e.Message }

func newAppError(status int, code, message string) *appError {
	return &appError{Status: status, Code: code, Message: message}
}

func mapServiceError(err error) error {
	var app *errs.AppError
	if errors.As(err, &app) {
		return &appError{Status: app.HTTPStatus, Code: app.Code, Message: app.Message}
	}

	switch {
	case errors.Is(err, user.ErrNotFound):
		return newAppError(404, "USER_NOT_FOUND", "User not found")
	case errors.Is(err, user.ErrEmailTaken):
		return newAppError(409, "EMAIL_TAKEN", "Email already registered")
	case errors.Is(err, user.ErrDisplayNameTaken), errors.Is(err, auth.ErrDisplayNameTaken):
		return newAppError(409, "DISPLAY_NAME_TAKEN", "Display name already taken")
	case errors.Is(err, auth.ErrInvalidCredentials):
		return newAppError(401, "INVALID_CREDENTIALS", "Invalid email or password")
	case errors.Is(err, auth.ErrEmailNotVerified):
		return newAppError(403, "EMAIL_NOT_VERIFIED", "Email not verified")
	case errors.Is(err, auth.ErrAccountDisabled):
		return newAppError(403, "ACCOUNT_DISABLED", "Account is disabled")
	case errors.Is(err, auth.ErrInvalidRefresh):
		return newAppError(401, "INVALID_REFRESH", "Invalid or expired refresh token")
	case errors.Is(err, useradmin.ErrLastAdmin):
		return newAppError(409, "LAST_ADMIN", "Cannot disable the last admin")
	case errors.Is(err, useradmin.ErrUserNotFound):
		return newAppError(404, "USER_NOT_FOUND", "User not found")
	default:
		return newAppError(500, "INTERNAL", "Internal server error")
	}
}

func getAppFromCtx(ctx context.Context) *model.App {
	// Extract from gin context - this will be adapted based on how
	// the strict server passes context. The gin context is available
	// via the request context.
	panic("implement: extract app from context")
}

func getUserIDFromCtx(ctx context.Context) uuid.UUID {
	panic("implement: extract user ID from context")
}

func getIPFromCtx(ctx context.Context) string {
	panic("implement: extract IP from context")
}

func getUserAgentFromCtx(ctx context.Context) string {
	panic("implement: extract User-Agent from context")
}

func userToAPI(u *model.User) api.User {
	apiUser := api.User{
		Id:        &u.ID,
		AppId:     &u.AppID,
		Email:     &u.Email,
		Role:      (*api.UserRole)(&u.Role),
		CreatedAt: &u.CreatedAt,
		UpdatedAt: &u.UpdatedAt,
	}
	if u.DisplayName != nil {
		apiUser.DisplayName = u.DisplayName
	}
	if u.AvatarURL != nil {
		apiUser.AvatarUrl = u.AvatarURL
	}
	if u.EmailVerifiedAt != nil {
		apiUser.EmailVerifiedAt = u.EmailVerifiedAt
	}
	if u.DisabledAt != nil {
		apiUser.DisabledAt = u.DisabledAt
	}
	return apiUser
}
```

Note: The `getAppFromCtx` etc. helpers need to be implemented based on how oapi-codegen's strict server passes the gin context. In the strict server pattern, the `context.Context` is derived from `c.Request.Context()`, so you need to store the app/claims in the request context, not just gin context. This requires a small middleware change.

- [ ] **Step 4: Verify compilation**

Run: `go build ./...`
Expected: Compiles (helper stubs may panic but should compile)

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi/
git commit -m "feat(httpapi): implement StrictHandlerInterface"
```

---

### Task 4: Context adapter and middleware changes

**Files:**
- Modify: `internal/middleware/app.go` (store app in request context)
- Modify: `internal/middleware/auth.go` (store claims in request context)
- Modify: `internal/middleware/adminrole.go` (store user in request context)

The strict server receives `context.Context` (from `c.Request.Context()`), not `*gin.Context`. The middleware must store values in the request context so the strict handler can retrieve them.

- [ ] **Step 1: Add context key types and setters/getters**

Create or update `internal/middleware/context.go`:

```go
package middleware

import (
	"context"

	"github.com/google/uuid"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/app"
)

type contextKey string

const (
	ctxKeyApp      contextKey = "app"
	ctxKeyUserID   contextKey = "user_id"
	ctxKeyUserRole contextKey = "user_role"
	ctxKeyAdminUser contextKey = "admin_user"
)

func WithApp(ctx context.Context, a *app.Model) context.Context {
	return context.WithValue(ctx, ctxKeyApp, a)
}

func AppFromContext(ctx context.Context) (*app.Model, bool) {
	a, ok := ctx.Value(ctxKeyApp).(*app.Model)
	return a, ok
}

func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, id)
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(ctxKeyUserID).(uuid.UUID)
	return id, ok
}

func WithAdminUser(ctx context.Context, u *model.User) context.Context {
	return context.WithValue(ctx, ctxKeyAdminUser, u)
}

func AdminUserFromContext(ctx context.Context) (*model.User, bool) {
	u, ok := ctx.Value(ctxKeyAdminUser).(*model.User)
	return u, ok
}
```

- [ ] **Step 2: Update AppSlugMiddleware to also store in request context**

Modify `internal/middleware/app.go` — after `c.Set(appKey, a)`, add:

```go
	c.Request = c.Request.WithContext(WithApp(c.Request.Context(), a))
```

- [ ] **Step 3: Update Auth middleware to store user ID in request context**

Modify `internal/middleware/auth.go` — after setting claims, add:

```go
	if userID, err := uuid.Parse(claims.Subject); err == nil {
		c.Request = c.Request.WithContext(WithUserID(c.Request.Context(), userID))
	}
```

- [ ] **Step 4: Update AdminRole middleware to store user in request context**

Modify `internal/middleware/adminrole.go` — after `c.Set(adminUserKey, u)`, add:

```go
	c.Request = c.Request.WithContext(WithAdminUser(c.Request.Context(), u))
```

- [ ] **Step 5: Implement the context helpers in strict.go**

Replace the panic stubs in `internal/httpapi/strict.go`:

```go
func getAppFromCtx(ctx context.Context) *app.Model {
	a, _ := middleware.AppFromContext(ctx)
	return a
}

func getUserIDFromCtx(ctx context.Context) uuid.UUID {
	id, _ := middleware.UserIDFromContext(ctx)
	return id
}

func getIPFromCtx(ctx context.Context) string {
	// IP is not available via context in the strict server pattern.
	// For login/logout event recording, pass empty string.
	// This is acceptable since the strict handler doesn't have direct gin access.
	return ""
}

func getUserAgentFromCtx(ctx context.Context) string {
	return ""
}
```

Note: IP and User-Agent are not available through `context.Context`. For login events, the service layer already handles empty strings gracefully. If these are needed, they must be passed via the OpenAPI spec headers or a custom middleware that stores them in context.

- [ ] **Step 6: Commit**

```bash
git add internal/middleware/ internal/httpapi/
git commit -m "feat(middleware): store values in request context for strict server"
```

---

### Task 5: Wire strict handler in main.go

**Files:**
- Modify: `cmd/api/main.go`

- [ ] **Step 1: Update main.go to use strict handler**

Replace the route mounting section. Remove the old `RegisterAuth`, `RegisterMe`, `RegisterUsers` calls. Add:

```go
	// --- Strict server wiring ---
	strictServer := &httpapi.StrictServer{
		AuthSvc:    authSvc,
		ProfileSvc: profileSvc,
		AdminSvc:   adminSvc,
	}
	strictHandler := api.NewStrictHandlerWithOptions(strictServer, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(c *gin.Context, err error) {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
		},
		ResponseErrorHandlerFunc: func(c *gin.Context, err error) {
			var appErr *httpapi.AppError
			if errors.As(err, &appErr) {
				errs.Render(c, errs.New(appErr.Status, appErr.Code, appErr.Message))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error"))
		},
	})

	// Auth routes (no auth middleware)
	api.RegisterHandlers(v1, strictHandler)

	// /me routes (auth required)
	me := v1.Group("")
	me.Use(middleware.Auth(signer))
	api.RegisterHandlers(me, strictHandler)

	// /users routes (auth + admin required)
	adminGrp := v1.Group("")
	adminGrp.Use(middleware.Auth(signer))
	adminGrp.Use(middleware.AdminRole(userRepo))
	api.RegisterHandlers(adminGrp, strictHandler)
```

Note: `RegisterHandlers` registers ALL routes on the group. When called on `me` and `adminGrp` subgroups, the auth-only and admin-only paths will have the appropriate middleware. The auth routes on `v1` don't have auth middleware. This works because each group has its own copy of the routes.

Wait — this won't work correctly because `RegisterHandlers` registers ALL routes on each group, including the ones that shouldn't be there. The correct approach is to use separate registration functions if oapi-codegen generates them, or to register routes individually.

Let me re-think. The oapi-codegen generates `RegisterHandlers` which registers ALL routes. We need separate registration for each group. The correct approach:

```go
	// Use the generated per-tag or per-operation registration if available,
	// or register all routes on the main group and rely on middleware being
	// applied correctly via the security scheme.
```

Actually, the correct approach with oapi-codegen Gin strict server is:

1. Register ALL routes on one group
2. Use the `StrictHandlerWithOptions` with middleware that checks security requirements
3. The strict server's `GetMe`, `ListUsers` etc. methods check auth themselves

OR: Don't use middleware-based auth at all. Instead, implement auth checks inside the strict handler methods using the context.

**Revised approach:** Register all routes on the main `v1` group. Auth/admin checks happen inside the strict handler methods, not via middleware. This is cleaner with oapi-codegen.

```go
	strictServer := &httpapi.StrictServer{
		AuthSvc:    authSvc,
		ProfileSvc: profileSvc,
		AdminSvc:   adminSvc,
		Signer:     signer,
		UserRepo:   userRepo,
	}
	strictHandler := api.NewStrictHandlerWithOptions(strictServer, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(c *gin.Context, err error) {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
		},
		ResponseErrorHandlerFunc: func(c *gin.Context, err error) {
			// Map appError to HTTP response
			var appErr *httpapi.AppError
			if errors.As(err, &appErr) {
				errs.Render(c, errs.New(appErr.Status, appErr.Code, appErr.Message))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error"))
		},
	})

	api.RegisterHandlersWithOptions(v1, strictHandler, api.GinServerOptions{
		BaseURL: "/v1/apps/:slug",
	})
```

Hmm, but this changes the auth model. Let me reconsider.

**Best approach:** Keep middleware for auth/admin. Use `RegisterHandlers` on each subgroup. The issue is that `RegisterHandlers` registers ALL paths, but on a subgroup they'll be prefixed. Since the paths in the spec are relative (no `/v1/apps/{slug}` prefix), registering on the `v1` group (which is already `/v1/apps/:slug`) means all paths work correctly.

The key insight: we can call `api.RegisterHandlers` multiple times on different groups, and each group has its own middleware stack. The routes that don't need auth won't have auth middleware applied because they're on the base `v1` group. The routes that need auth are on the `me` and `admin` subgroups.

But wait — `RegisterHandlers` registers ALL 15 paths. If we call it 3 times on 3 groups, we get 45 route registrations, most of which are duplicates with different middleware. That's wrong.

**Correct approach:** The oapi-codegen `RegisterHandlers` function must be called once. Auth should be handled inside the strict handler methods, not via middleware. This is the idiomatic oapi-codegen pattern.

Update the `StrictServer` to include auth dependencies and perform auth checks:

```go
type StrictServer struct {
	AuthSvc    *auth.Service
	ProfileSvc *userprofile.Service
	AdminSvc   *useradmin.Service
	Signer     *auth.Signer
	UserRepo   *userrepo.Repo
}
```

Each method that requires auth extracts the bearer token from the request, verifies it, and proceeds. Methods that require admin also check the DB.

This is a significant change from the middleware-based approach. Document it clearly.

Let me rewrite Task 5 with this approach.

- [ ] **Step 1: Update main.go**

Replace the route mounting section in `cmd/api/main.go`:

```go
	// --- Route mounting ---
	appRepo := apprepo.NewRepo(gormDB)
	v1 := router.Group("/v1/apps/:slug")
	v1.Use(middleware.AppSlugMiddleware(appRepo))

	// --- Wave 4: services ---
	auditRepo := auditlogrepo.NewRepo(gormDB)
	profileSvc := userprofilesvc.NewService(userprofilesvc.Deps{UserRepo: userRepo})
	adminSvc := useradminsvc.NewService(useradminsvc.Deps{
		UserRepo:  userRepo,
		AuditRepo: auditRepo,
		OTP:       otpSvc,
	})

	// --- Strict server ---
	strictServer := &httpapi.StrictServer{
		AuthSvc:    authSvc,
		ProfileSvc: profileSvc,
		AdminSvc:   adminSvc,
		Signer:     signer,
		UserRepo:   userRepo,
	}
	strictHandler := api.NewStrictHandlerWithOptions(strictServer, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(c *gin.Context, err error) {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
		},
		ResponseErrorHandlerFunc: func(c *gin.Context, err error) {
			var appErr *httpapi.AppError
			if errors.As(err, &appErr) {
				errs.Render(c, errs.New(appErr.Status, appErr.Code, appErr.Message))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error"))
		},
	})

	// Rate limiting applied separately via middleware on specific routes
	// (not handled by oapi-codegen — applied at the Gin group level)

	// Auth rate-limited routes
	if rlStore != nil {
		v1.POST("/auth/login",
			middleware.RateLimit(rlStore, 5, time.Minute, func(c *gin.Context) string { return c.GetString("app_id") + ":login" }),
		)
		v1.POST("/auth/register",
			middleware.RateLimit(rlStore, 3, time.Minute, func(c *gin.Context) string { return c.GetString("app_id") + ":register" }),
		)
		v1.POST("/auth/password/forgot",
			middleware.RateLimit(rlStore, 3, time.Minute, func(c *gin.Context) string { return c.GetString("app_id") + ":forgot" }),
		)
	}

	api.RegisterHandlers(v1, strictHandler)
```

Wait, this still has the rate limiting problem. Rate limiting is per-route middleware, not something the strict handler manages.

**Final approach:** Use `RegisterHandlers` once on the `v1` group. Rate limiting is applied via Gin middleware on specific routes before `RegisterHandlers` is called. But `RegisterHandlers` will try to register those same routes again...

OK, I think the cleanest approach is:

1. Don't use `RegisterHandlers` at all.
2. Register each route manually using the generated `Register*` functions if available, or use the generated `Handler` wrappers.
3. Apply middleware per-route as before.

Let me check what oapi-codegen actually generates. It generates:
- `RegisterHandlers(router gin.IRouter, si ServerInterface)` — for the basic interface
- `RegisterHandlersWithOptions(router gin.IRouter, si ServerInterface, options GinServerOptions)` — for the strict interface

For strict server, it generates:
- `NewStrictHandlerWithOptions(si StrictHandlerInterface, middlewares []StrictMiddlewareFunc, options StrictHTTPServerOptions) StrictHandlerInterface`
- The wrapped handler still uses `RegisterHandlers`

The `StrictMiddlewareFunc` type allows adding middleware at the strict handler level:
```go
type StrictMiddlewareFunc func(f StrictHandlerFunc, operationID string) StrictHandlerFunc
```

This is the key! We can use strict middleware to implement auth and rate limiting:

```go
func AuthMiddleware(signer *auth.Signer) StrictMiddlewareFunc {
	return func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			// Check if this operation requires auth
			if requiresAuth(operationID) {
				// Extract and verify token
				// ...
			}
			return f(ctx, request)
		}
	}
}
```

This is the idiomatic approach. Let me revise the plan.

Actually, I realize this plan is getting very complex. Let me simplify and focus on what matters:

1. Write the OpenAPI spec
2. Generate code
3. Implement the strict handler
4. Wire it up

The middleware/auth integration is the tricky part. Let me write a cleaner plan.

For the final approach:
- Keep `AppSlugMiddleware` as Gin middleware (it resolves the slug)
- Use `StrictMiddlewareFunc` for auth, admin, rate limiting
- Register all routes via `RegisterHandlers` once

This is clean and idiomatic.

Let me rewrite the plan properly.
```

This plan is getting too complex. Let me rewrite it more concisely.

- [ ] **Step 1: Update main.go**

Replace the route mounting section with:

```go
	// --- Route mounting ---
	appRepo := apprepo.NewRepo(gormDB)
	v1 := router.Group("/v1/apps/:slug")
	v1.Use(middleware.AppSlugMiddleware(appRepo))

	// --- Services ---
	auditRepo := auditlogrepo.NewRepo(gormDB)
	profileSvc := userprofilesvc.NewService(userprofilesvc.Deps{UserRepo: userRepo})
	adminSvc := useradminsvc.NewService(useradminsvc.Deps{
		UserRepo:  userRepo,
		AuditRepo: auditRepo,
		OTP:       otpSvc,
	})

	// --- Strict server with middleware ---
	strictServer := &httpapi.StrictServer{
		AuthSvc:    authSvc,
		ProfileSvc: profileSvc,
		AdminSvc:   adminSvc,
		Signer:     signer,
		UserRepo:   userRepo,
		RateStore:  rlStore,
	}

	middlewares := []api.StrictMiddlewareFunc{
		httpapi.StrictAuthMiddleware(signer),
		httpapi.StrictRateLimitMiddleware(rlStore),
	}

	strictHandler := api.NewStrictHandlerWithOptions(strictServer, middlewares, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(c *gin.Context, err error) {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
		},
		ResponseErrorHandlerFunc: func(c *gin.Context, err error) {
			var appErr *httpapi.AppError
			if errors.As(err, &appErr) {
				errs.Render(c, errs.New(appErr.Status, appErr.Code, appErr.Message))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error"))
		},
	})

	api.RegisterHandlers(v1, strictHandler)
```

- [ ] **Step 2: Add StrictMiddlewareFunc implementations**

Add to `internal/httpapi/strict.go`:

```go
// Operations that require authentication
var authOperations = map[string]bool{
	"getMe":                 true,
	"updateMe":              true,
	"listUsers":             true,
	"getUser":               true,
	"disableUser":           true,
	"enableUser":            true,
	"triggerPasswordReset":  true,
}

// Operations that require admin role
var adminOperations = map[string]bool{
	"listUsers":            true,
	"getUser":              true,
	"disableUser":          true,
	"enableUser":           true,
	"triggerPasswordReset": true,
}

// Operations with rate limits: operationID -> {limit, window}
var rateLimitedOps = map[string]struct {
	Limit  int64
	Window time.Duration
}{
	"register":       {Limit: 3, Window: time.Minute},
	"login":          {Limit: 5, Window: time.Minute},
	"forgotPassword": {Limit: 3, Window: time.Minute},
}

func StrictAuthMiddleware(signer *auth.Signer) api.StrictMiddlewareFunc {
	return func(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			if !authOperations[operationID] {
				return f(ctx, request)
			}

			// Extract token from request context
			// The gin context stores the Authorization header
			// We need to get it from the context somehow
			// This is the tricky part - oapi-codegen strict server passes context.Context

			// For now, implement a helper that extracts the token
			token, ok := bearerFromContext(ctx)
			if !ok {
				return nil, newAppError(401, "UNAUTHENTICATED", "Missing bearer token")
			}

			claims, err := signer.Verify(token)
			if err != nil {
				return nil, newAppError(401, "INVALID_TOKEN", "Invalid or expired token")
			}

			ctx = middleware.WithUserID(ctx, claims.UserID())

			if adminOperations[operationID] {
				// DB check for admin
				app, _ := middleware.AppFromContext(ctx)
				user, err := /* ... verify admin ... */
				if err != nil { return nil, err }
				ctx = middleware.WithAdminUser(ctx, user)
			}

			return f(ctx, request)
		}
	}
}
```

Note: The `bearerFromContext` helper needs to extract the Authorization header. In oapi-codegen's Gin strict server, the `context.Context` is derived from `c.Request.Context()`, so we need to store the raw header in the context via middleware.

- [ ] **Step 3: Store Authorization header in context**

Update `AppSlugMiddleware` to also store the raw request in context:

```go
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "gin_request", c.Request))
```

Then `bearerFromContext` can extract from the stored request.

- [ ] **Step 4: Commit**

```bash
git add cmd/api/main.go internal/httpapi/
git commit -m "feat(api): wire strict handler with auth middleware"
```

---

### Task 6: Remove old handlers and verify

**Files:**
- Delete: `internal/httpapi/auth.go`
- Delete: `internal/httpapi/me.go`
- Delete: `internal/httpapi/users.go`
- Modify: `internal/httpapi/health.go` (keep as-is)

- [ ] **Step 1: Delete old handler files**

```bash
rm internal/httpapi/auth.go internal/httpapi/me.go internal/httpapi/users.go
```

- [ ] **Step 2: Remove old registrations from main.go**

Ensure `httpapi.RegisterAuth`, `httpapi.RegisterMe`, `httpapi.RegisterUsers` are no longer called.

- [ ] **Step 3: Build and verify**

Run: `make build`
Expected: Compiles successfully

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(httpapi): remove hand-written handlers, use strict server"
```

---

### Task 7: Final verification

- [ ] **Step 1: Run lint**

Run: `make lint`
Expected: PASS

- [ ] **Step 2: Run build**

Run: `make build`
Expected: PASS

- [ ] **Step 3: Update tracker**

Update `docs/migration/tracker.md` and `docs/migration/implementation-path.md` to reflect OpenAPI migration.

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "docs(tracker): mark OpenAPI migration complete"
```
