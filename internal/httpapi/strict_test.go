package httpapi

import (
	"testing"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	api "github.com/nathan-tsien/iam/api"
	"github.com/nathan-tsien/iam/internal/model"
)

// --- AppError tests ---

func TestAppError_Error(t *testing.T) {
	err := &AppError{Status: 401, Code: "UNAUTHENTICATED", Message: "Missing bearer token"}
	if got := err.Error(); got != "Missing bearer token" {
		t.Errorf("AppError.Error() = %q, want %q", got, "Missing bearer token")
	}
}

func TestAppError_Fields(t *testing.T) {
	err := &AppError{Status: 403, Code: "FORBIDDEN", Message: "Admin access required"}
	if err.Status != 403 {
		t.Errorf("AppError.Status = %d, want 403", err.Status)
	}
	if err.Code != "FORBIDDEN" {
		t.Errorf("AppError.Code = %q, want %q", err.Code, "FORBIDDEN")
	}
}

// --- Operation map consistency tests ---

func TestAdminRequiredOpsSubsetOfAuthRequired(t *testing.T) {
	for op := range adminRequiredOps {
		if !authRequiredOps[op] {
			t.Errorf("adminRequiredOps[%q] = true, but authRequiredOps[%q] = false; admin ops must be a subset of auth ops", op, op)
		}
	}
}

func TestAuthRequiredOpsContent(t *testing.T) {
	expected := map[string]bool{
		"GetMe":                true,
		"UpdateMe":             true,
		"ListUsers":            true,
		"GetUser":              true,
		"DisableUser":          true,
		"EnableUser":           true,
		"TriggerPasswordReset": true,
		"GetMeSessions":        true,
		"DeleteMeSession":      true,
		"DeleteMeSessions":     true,
		"GetMeLoginHistory":    true,
		"DeleteMe":             true,
	}
	for op, want := range expected {
		if got := authRequiredOps[op]; got != want {
			t.Errorf("authRequiredOps[%q] = %v, want %v", op, got, want)
		}
	}
	for op := range authRequiredOps {
		if _, ok := expected[op]; !ok {
			t.Errorf("authRequiredOps contains unexpected operation %q", op)
		}
	}
}

func TestAdminRequiredOpsContent(t *testing.T) {
	expected := map[string]bool{
		"ListUsers":            true,
		"GetUser":              true,
		"DisableUser":          true,
		"EnableUser":           true,
		"TriggerPasswordReset": true,
	}
	for op, want := range expected {
		if got := adminRequiredOps[op]; got != want {
			t.Errorf("adminRequiredOps[%q] = %v, want %v", op, got, want)
		}
	}
	for op := range adminRequiredOps {
		if _, ok := expected[op]; !ok {
			t.Errorf("adminRequiredOps contains unexpected operation %q", op)
		}
	}
}

func TestRateLimitOpsConfig(t *testing.T) {
	tests := []struct {
		op     string
		max    int64
		window time.Duration
	}{
		{"Register", 3, time.Minute},
		{"Login", 5, time.Minute},
		{"ForgotPassword", 3, time.Minute},
		{"ListUsers", 100, time.Minute},
		{"DeleteMe", 5, time.Minute},
	}

	for _, tt := range tests {
		cfg, ok := rateLimitOps[tt.op]
		if !ok {
			t.Errorf("rateLimitOps missing operation %q", tt.op)
			continue
		}
		if cfg.Max != tt.max {
			t.Errorf("rateLimitOps[%q].Max = %d, want %d", tt.op, cfg.Max, tt.max)
		}
		if cfg.Window != tt.window {
			t.Errorf("rateLimitOps[%q].Window = %v, want %v", tt.op, cfg.Window, tt.window)
		}
	}

	expectedOps := map[string]bool{
		"Register": true, "Login": true, "ForgotPassword": true, "ListUsers": true, "DeleteMe": true,
	}
	for op := range rateLimitOps {
		if !expectedOps[op] {
			t.Errorf("rateLimitOps contains unexpected operation %q", op)
		}
	}
}

func TestRateLimitOpsNotInAuthRequired(t *testing.T) {
	// Rate-limited public endpoints should NOT be in authRequiredOps
	publicRateLimited := []string{"Register", "Login", "ForgotPassword"}
	for _, op := range publicRateLimited {
		if authRequiredOps[op] {
			t.Errorf("public rate-limited operation %q should not be in authRequiredOps", op)
		}
	}
}

// --- userToAPI tests ---

func TestUserToAPI_AllFields(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	now := time.Now()
	displayName := "Test User"
	avatarURL := "https://example.com/avatar.png"

	u := &model.User{
		ID:              userID,
		AppID:           appID,
		Email:           "test@example.com",
		Role:            model.RoleAdmin,
		DisplayName:     &displayName,
		AvatarURL:       &avatarURL,
		EmailVerifiedAt: &now,
		DisabledAt:      nil,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	apiUser := userToAPI(u)

	if apiUser.Id != openapi_types.UUID(userID) {
		t.Errorf("userToAPI.Id = %v, want %v", apiUser.Id, userID)
	}
	if apiUser.AppId != openapi_types.UUID(appID) {
		t.Errorf("userToAPI.AppId = %v, want %v", apiUser.AppId, appID)
	}
	if apiUser.Email != "test@example.com" {
		t.Errorf("userToAPI.Email = %q, want %q", apiUser.Email, "test@example.com")
	}
	if apiUser.Role != api.UserRole("admin") {
		t.Errorf("userToAPI.Role = %q, want %q", apiUser.Role, "admin")
	}
	if apiUser.DisplayName == nil || *apiUser.DisplayName != "Test User" {
		t.Errorf("userToAPI.DisplayName = %v, want %q", apiUser.DisplayName, "Test User")
	}
	if apiUser.AvatarUrl == nil || *apiUser.AvatarUrl != "https://example.com/avatar.png" {
		t.Errorf("userToAPI.AvatarUrl = %v, want %q", apiUser.AvatarUrl, "https://example.com/avatar.png")
	}
	if apiUser.EmailVerifiedAt == nil || !apiUser.EmailVerifiedAt.Equal(now) {
		t.Errorf("userToAPI.EmailVerifiedAt = %v, want %v", apiUser.EmailVerifiedAt, now)
	}
	if apiUser.DisabledAt != nil {
		t.Errorf("userToAPI.DisabledAt = %v, want nil", apiUser.DisabledAt)
	}
	if !apiUser.CreatedAt.Equal(now) {
		t.Errorf("userToAPI.CreatedAt = %v, want %v", apiUser.CreatedAt, now)
	}
	if !apiUser.UpdatedAt.Equal(now) {
		t.Errorf("userToAPI.UpdatedAt = %v, want %v", apiUser.UpdatedAt, now)
	}
}

func TestUserToAPI_NilOptionalFields(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	now := time.Now()

	u := &model.User{
		ID:              userID,
		AppID:           appID,
		Email:           "user@example.com",
		Role:            model.RoleUser,
		DisplayName:     nil,
		AvatarURL:       nil,
		EmailVerifiedAt: nil,
		DisabledAt:      nil,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	apiUser := userToAPI(u)

	if apiUser.DisplayName != nil {
		t.Errorf("userToAPI.DisplayName = %v, want nil", apiUser.DisplayName)
	}
	if apiUser.AvatarUrl != nil {
		t.Errorf("userToAPI.AvatarUrl = %v, want nil", apiUser.AvatarUrl)
	}
	if apiUser.EmailVerifiedAt != nil {
		t.Errorf("userToAPI.EmailVerifiedAt = %v, want nil", apiUser.EmailVerifiedAt)
	}
	if apiUser.DisabledAt != nil {
		t.Errorf("userToAPI.DisabledAt = %v, want nil", apiUser.DisabledAt)
	}
	if apiUser.Role != api.UserRole("user") {
		t.Errorf("userToAPI.Role = %q, want %q", apiUser.Role, "user")
	}
}

func TestUserToAPI_DisabledUser(t *testing.T) {
	userID := uuid.New()
	appID := uuid.New()
	now := time.Now()
	disabledAt := now.Add(-24 * time.Hour)
	displayName := "Disabled User"

	u := &model.User{
		ID:              userID,
		AppID:           appID,
		Email:           "disabled@example.com",
		Role:            model.RoleUser,
		DisplayName:     &displayName,
		AvatarURL:       nil,
		EmailVerifiedAt: &now,
		DisabledAt:      &disabledAt,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	apiUser := userToAPI(u)

	if apiUser.DisabledAt == nil || !apiUser.DisabledAt.Equal(disabledAt) {
		t.Errorf("userToAPI.DisabledAt = %v, want %v", apiUser.DisabledAt, disabledAt)
	}
	if apiUser.EmailVerifiedAt == nil || !apiUser.EmailVerifiedAt.Equal(now) {
		t.Errorf("userToAPI.EmailVerifiedAt = %v, want %v", apiUser.EmailVerifiedAt, now)
	}
}

func TestUserToAPI_RoleMapping(t *testing.T) {
	tests := []struct {
		role     model.Role
		wantRole api.UserRole
	}{
		{model.RoleUser, api.UserRole("user")},
		{model.RoleAdmin, api.UserRole("admin")},
	}

	for _, tt := range tests {
		u := &model.User{
			ID:    uuid.New(),
			AppID: uuid.New(),
			Email: "test@example.com",
			Role:  tt.role,
		}
		apiUser := userToAPI(u)
		if apiUser.Role != tt.wantRole {
			t.Errorf("userToAPI(Role=%q).Role = %q, want %q", tt.role, apiUser.Role, tt.wantRole)
		}
	}
}

// --- ptrMap tests ---

func TestPtrMap(t *testing.T) {
	m := map[string]interface{}{"key": "value"}
	result := ptrMap(m)

	if result == nil {
		t.Fatal("ptrMap() returned nil")
	}
	if (*result)["key"] != "value" {
		t.Errorf("ptrMap()[\"key\"] = %v, want %q", (*result)["key"], "value")
	}

	// Verify it points to the same map
	(*result)["key2"] = "value2"
	if m["key2"] != "value2" {
		t.Error("ptrMap() did not return a pointer to the original map")
	}
}

// --- Compile-time interface check ---

func TestStrictServerImplementsInterface(t *testing.T) {
	// This is already checked at compile time with the var _ api.StrictServerInterface = (*StrictServer)(nil)
	// in strict.go, but we verify it here as a runtime sanity check.
	var _ api.StrictServerInterface = (*StrictServer)(nil)
}
