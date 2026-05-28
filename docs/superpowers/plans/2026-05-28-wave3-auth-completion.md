# Wave 3: Auth Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the public auth surface with password forgot/reset, SMTP mail, rate limiting, and login events.

**Architecture:** Four independent modules added to existing Wave 2 structure. SMTP mailer lifted from family-office-platform. Rate limiting uses Redis with memory fallback. Login events are best-effort async writes.

**Tech Stack:** Go 1.25+, Gin, GORM, net/smtp, go-redis/v9, sync.Map

---

## Task 1: Password Forgot/Reset Service

**Files:**
- Modify: `internal/service/auth/auth.go`

Add `ForgotPassword` and `ResetPassword` methods to existing auth service.

- [ ] **Step 1: Add ForgotPassword method**

Add to `internal/service/auth/auth.go`:

```go
// ForgotPassword sends a password reset OTP. Returns nil even if email
// doesn't exist to prevent user enumeration.
func (s *Service) ForgotPassword(ctx context.Context, appID uuid.UUID, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil // Don't leak user existence
		}
		return err
	}
	if !u.EmailVerified() {
		return nil // Don't leak unverified status
	}
	// Ignore OTP send errors to prevent enumeration
	_ = s.OTP.Issue(ctx, appID, email, mail.PurposePasswordReset)
	return nil
}
```

- [ ] **Step 2: Add ResetPassword method**

Add to `internal/service/auth/auth.go`:

```go
// ResetPassword verifies the reset OTP and sets a new password.
func (s *Service) ResetPassword(ctx context.Context, appID uuid.UUID, email, code, newPassword string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if fails := passwordpolicy.Validate(newPassword); len(fails) > 0 {
		return &ErrWeakPassword{FailedRules: fails}
	}
	if err := s.OTP.Consume(ctx, appID, email, code, mail.PurposePasswordReset); err != nil {
		return err
	}
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		return err
	}
	hash, err := pkgauth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.UserRepo.UpdatePassword(ctx, appID, u.ID, hash); err != nil {
		return err
	}
	// Revoke all refresh tokens after password reset
	return s.RefreshRepo.RevokeAllForUser(ctx, u.ID)
}
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/service/auth/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/service/auth/
git commit -m "feat(service/auth): add ForgotPassword and ResetPassword"
```

---

## Task 2: Password Forgot/Reset HTTP Handlers

**Files:**
- Modify: `internal/httpapi/auth.go`

Add HTTP handlers for password forgot and reset endpoints.

- [ ] **Step 1: Add route registration**

Update `RegisterAuth` in `internal/httpapi/auth.go`:

```go
func RegisterAuth(r *gin.RouterGroup, authSvc *auth.Service) {
	r.POST("/auth/register", handleRegister(authSvc))
	r.POST("/auth/check-availability", handleCheckAvailability(authSvc))
	r.POST("/auth/otp/verify", handleVerifyOTP(authSvc))
	r.POST("/auth/login", handleLogin(authSvc))
	r.POST("/auth/refresh", handleRefresh(authSvc))
	r.POST("/auth/logout", handleLogout(authSvc))
	r.POST("/auth/password/forgot", handleForgotPassword(authSvc))
	r.POST("/auth/password/reset", handleResetPassword(authSvc))
}
```

- [ ] **Step 2: Add handleForgotPassword**

```go
func handleForgotPassword(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email string `json:"email" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		// Always return 200 to prevent user enumeration
		_ = authSvc.ForgotPassword(c.Request.Context(), app.ID, req.Email)
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset code has been sent"})
	}
}
```

- [ ] **Step 3: Add handleResetPassword**

```go
func handleResetPassword(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email       string `json:"email" binding:"required"`
			Code        string `json:"code" binding:"required"`
			NewPassword string `json:"new_password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if err := authSvc.ResetPassword(c.Request.Context(), app.ID, req.Email, req.Code, req.NewPassword); err != nil {
			switch e := err.(type) {
			case *auth.ErrWeakPassword:
				errs.Render(c, errs.New(http.StatusBadRequest, "WEAK_PASSWORD", "Password does not meet requirements").
					WithDetails(map[string]any{"failed_rules": e.FailedRules}))
			default:
				errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_OTP", "Invalid or expired reset code"))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
	}
}
```

- [ ] **Step 4: Verify compilation**

Run: `go build ./internal/httpapi/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi/
git commit -m "feat(httpapi): add password forgot/reset handlers"
```

---

## Task 3: SMTP Mail Provider

**Files:**
- Create: `internal/provider/mail/smtp.go`
- Create: `internal/provider/mail/templates/otp_en-US.txt`
- Create: `internal/provider/mail/templates/otp_zh-CN.txt`
- Create: `internal/provider/mail/templates/otp_zh-TW.txt`

Lift SMTP implementation from family-office-platform.

- [ ] **Step 1: Create templates directory and files**

Create `internal/provider/mail/templates/otp_en-US.txt`:
```
Subject: Your verification code
Your verification code is: {{.Code}}
Purpose: {{.Purpose}}
This code expires in 10 minutes.
```

Create `internal/provider/mail/templates/otp_zh-CN.txt`:
```
Subject: 您的验证码
您的验证码是：{{.Code}}
用途：{{.Purpose}}
此验证码将在10分钟后过期。
```

Create `internal/provider/mail/templates/otp_zh-TW.txt`:
```
Subject: 您的驗證碼
您的驗證碼是：{{.Code}}
用途：{{.Purpose}}
此驗證碼將在10分鐘後過期。
```

- [ ] **Step 2: Create smtp.go**

```go
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/*.txt
var templateFS embed.FS

var otpTemplates = func() *template.Template {
	t := template.New("otp")
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		panic("mail: read embedded templates: " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "otp_") {
			continue
		}
		data, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			panic("mail: read template " + e.Name() + ": " + err.Error())
		}
		if _, err := t.New(e.Name()).Parse(string(data)); err != nil {
			panic("mail: parse template " + e.Name() + ": " + err.Error())
		}
	}
	return t
}()

type SMTPConfig struct {
	Host        string
	Port        int
	User        string
	Password    string
	FromAddress string
	FromName    string
	Timeout     time.Duration
}

type smtpMailer struct {
	cfg    SMTPConfig
	logger *slog.Logger
}

func NewSMTPMailer(cfg SMTPConfig, logger *slog.Logger) (Mailer, error) {
	if logger == nil {
		return nil, fmt.Errorf("nil logger")
	}
	return &smtpMailer{cfg: cfg, logger: logger}, nil
}

func RenderOTPMessage(locale Locale, code string, purpose Purpose) (subject, body string, err error) {
	name := "otp_" + string(locale) + ".txt"
	t := otpTemplates.Lookup(name)
	if t == nil {
		t = otpTemplates.Lookup("otp_zh-CN.txt")
		if t == nil {
			return "", "", fmt.Errorf("zh-CN template missing")
		}
	}
	var buf bytes.Buffer
	data := struct {
		Code    string
		Purpose string
	}{Code: code, Purpose: string(purpose)}
	if err := t.Execute(&buf, data); err != nil {
		return "", "", err
	}
	rendered := buf.String()
	rendered = strings.TrimPrefix(rendered, "﻿")
	if !strings.HasPrefix(rendered, "Subject:") {
		return "", "", fmt.Errorf("template %s does not start with Subject:", name)
	}
	idx := strings.Index(rendered, "\n")
	if idx < 0 {
		return "", "", fmt.Errorf("template %s missing newline after Subject", name)
	}
	subject = strings.TrimSpace(strings.TrimPrefix(rendered[:idx], "Subject:"))
	rest := rendered[idx+1:]
	rest = strings.TrimLeft(rest, "\r\n")
	return subject, rest, nil
}

func (m *smtpMailer) SendOTP(ctx context.Context, email, code string, purpose Purpose, locale Locale) error {
	subject, body, err := RenderOTPMessage(locale, code, purpose)
	if err != nil {
		return fmt.Errorf("render otp message: %w", err)
	}

	msg := buildMessage(m.cfg, email, subject, body)
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))

	deadline := time.Now().UTC().Add(m.cfg.Timeout)
	dialer := &net.Dialer{Deadline: deadline}
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Quit() }()

	auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(m.cfg.FromAddress); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(email); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp data write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}

	m.logger.InfoContext(ctx, "otp mail sent",
		"email", email,
		"purpose", string(purpose),
		"locale", string(locale),
	)
	return nil
}

func buildMessage(cfg SMTPConfig, to, subject, body string) string {
	from := cfg.FromAddress
	if cfg.FromName != "" {
		from = encodeHeaderWord(cfg.FromName) + " <" + cfg.FromAddress + ">"
	}
	headers := []string{
		"From: " + from,
		"To: " + to,
		"Subject: " + encodeHeaderWord(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
	}
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}

func encodeHeaderWord(s string) string {
	hasNonASCII := false
	for _, r := range s {
		if r > 127 {
			hasNonASCII = true
			break
		}
	}
	if !hasNonASCII {
		return s
	}
	const maxRawBytes = 45
	b := []byte(s)
	var words []string
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxRawBytes {
			chunk = b[:maxRawBytes]
			for len(chunk) > 0 && (chunk[len(chunk)-1]&0xC0) == 0x80 {
				chunk = chunk[:len(chunk)-1]
			}
			if len(chunk) == 0 {
				chunk = b[:maxRawBytes]
			}
		}
		words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString(chunk)+"?=")
		b = b[len(chunk):]
	}
	return strings.Join(words, " ")
}
```

- [ ] **Step 3: Update config for SMTP**

Add to `internal/config/config.go`:

```go
type Config struct {
	// ... existing fields ...
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFromAddr string
	SMTPFromName string
}
```

Load from env: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDR`, `SMTP_FROM_NAME`

- [ ] **Step 4: Update main.go mailer selection**

Update `cmd/api/main.go` to select mailer based on `APP_ENV`:

```go
var mailer mail.Mailer
if cfg.AppEnv == "production" {
	smtpCfg := mail.SMTPConfig{
		Host:        cfg.SMTPHost,
		Port:        cfg.SMTPPort,
		User:        cfg.SMTPUsername,
		Password:    cfg.SMTPPassword,
		FromAddress: cfg.SMTPFromAddr,
		FromName:    cfg.SMTPFromName,
		Timeout:     10 * time.Second,
	}
	mailer, err = mail.NewSMTPMailer(smtpCfg, slog.Default())
	if err != nil {
		log.Fatalf("init smtp mailer: %v", err)
	}
} else {
	mailer = &mail.LogMailer{}
}
```

- [ ] **Step 5: Verify compilation**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/provider/mail/ internal/config/ cmd/api/
git commit -m "feat(mail): add SMTP mailer with templates"
```

---

## Task 4: Rate Limiting - Interface and Memory Implementation

**Files:**
- Create: `internal/ratelimit/ratelimit.go`
- Create: `internal/ratelimit/memory/memory.go`

- [ ] **Step 1: Create ratelimit.go**

```go
package ratelimit

import (
	"context"
	"time"
)

// Store is the minimum surface a rate limit backend must support.
type Store interface {
	Incr(ctx context.Context, key string, ttlOnCreate time.Duration) (int64, error)
	Reset(ctx context.Context, key string) error
}

// Allow returns (true, remaining, nil) when a request is within budget and
// (false, 0, nil) when exceeded.
func Allow(ctx context.Context, store Store, key string, max int64, window time.Duration) (bool, int64, error) {
	count, err := store.Incr(ctx, key, window)
	if err != nil {
		return false, 0, err
	}
	if count > max {
		return false, 0, nil
	}
	return true, max - count, nil
}
```

- [ ] **Step 2: Create memory/memory.go**

```go
package memory

import (
	"context"
	"sync"
	"time"
)

type entry struct {
	count     int64
	expiresAt time.Time
}

// Store is a goroutine-safe in-memory counter with per-key TTL.
type Store struct {
	mu   sync.Mutex
	data map[string]*entry
}

func NewStore() *Store {
	return &Store{data: make(map[string]*entry)}
}

func (s *Store) Incr(ctx context.Context, key string, ttlOnCreate time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	e, ok := s.data[key]
	if !ok || now.After(e.expiresAt) {
		e = &entry{count: 0, expiresAt: now.Add(ttlOnCreate)}
		s.data[key] = e
	}
	e.count++
	return e.count, nil
}

func (s *Store) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/ratelimit/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/ratelimit/
git commit -m "feat(ratelimit): add interface and memory store"
```

---

## Task 5: Rate Limiting - Redis Implementation

**Files:**
- Create: `internal/ratelimit/redis/redis.go`

- [ ] **Step 1: Create redis/redis.go**

```go
package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Store implements ratelimit.Store using Redis INCR + EXPIRE NX.
type Store struct {
	client *goredis.Client
}

func NewStore(client *goredis.Client) *Store {
	return &Store{client: client}
}

// Incr pipelines INCR + EXPIRE NX so the TTL is set only on the first increment.
func (s *Store) Incr(ctx context.Context, key string, ttlOnCreate time.Duration) (int64, error) {
	pipe := s.client.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.ExpireNX(ctx, key, ttlOnCreate)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (s *Store) Reset(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}
```

- [ ] **Step 2: Add go-redis dependency**

Run: `go get github.com/redis/go-redis/v9`

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/ratelimit/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/ratelimit/redis/ go.mod go.sum
git commit -m "feat(ratelimit): add Redis store"
```

---

## Task 6: Rate Limiting Middleware

**Files:**
- Create: `internal/middleware/ratelimit.go`

- [ ] **Step 1: Create ratelimit middleware**

```go
package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/ratelimit"
)

// RateLimit returns middleware that limits requests using the given store.
func RateLimit(store ratelimit.Store, max int64, window time.Duration, keyFunc func(c *gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFunc(c)
		allowed, remaining, err := ratelimit.Allow(c.Request.Context(), store, key, max, window)
		if err != nil {
			// On error, allow the request (fail open)
			c.Next()
			return
		}
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", max))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		if !allowed {
			errs.Render(c, errs.New(http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests"))
			c.Abort()
			return
		}
		c.Next()
	}
}

// LoginRateLimitKey generates rate limit key for login attempts.
func LoginRateLimitKey(c *gin.Context) string {
	app, _ := GetApp(c)
	if app == nil {
		return "unknown"
	}
	var req struct {
		Email string `json:"email"`
	}
	_ = c.ShouldBindJSON(&req)
	return fmt.Sprintf("%s:%s:login", app.ID.String(), req.Email)
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/middleware/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/middleware/
git commit -m "feat(middleware): add rate limit middleware"
```

---

## Task 7: Wire Rate Limiting in main.go

**Files:**
- Modify: `cmd/api/main.go`

- [ ] **Step 1: Add Redis client initialization**

Add to `cmd/api/main.go`:

```go
import (
	"github.com/redis/go-redis/v9"
	"github.com/nathan-tsien/iam/internal/ratelimit"
	ratelimitredis "github.com/nathan-tsien/iam/internal/ratelimit/redis"
	"github.com/nathan-tsien/iam/internal/ratelimit/memory"
)

// In main():
var ratelimitStore ratelimit.Store
redisURL := os.Getenv("REDIS_URL")
if redisURL != "" {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("parse redis url: %v", err)
	}
	redisClient := redis.NewClient(opt)
	ratelimitStore = ratelimitredis.NewStore(redisClient)
} else {
	ratelimitStore = memory.NewStore()
}
```

- [ ] **Step 2: Apply rate limiting to routes**

Update route mounting:

```go
v1 := r.Group("/v1/apps/:slug")
v1.Use(middleware.AppSlugMiddleware(appRepo))

// Rate limited routes
v1.POST("/auth/login", middleware.RateLimit(ratelimitStore, 5, time.Minute, loginRateLimitKey), handleLogin(authSvc))
v1.POST("/auth/register", middleware.RateLimit(ratelimitStore, 3, time.Minute, registerRateLimitKey), handleRegister(authSvc))
v1.POST("/auth/password/forgot", middleware.RateLimit(ratelimitStore, 3, time.Minute, forgotRateLimitKey), handleForgotPassword(authSvc))

// Non-rate-limited routes
v1.POST("/auth/check-availability", handleCheckAvailability(authSvc))
v1.POST("/auth/otp/verify", handleVerifyOTP(authSvc))
v1.POST("/auth/refresh", handleRefresh(authSvc))
v1.POST("/auth/logout", handleLogout(authSvc))
v1.POST("/auth/password/reset", handleResetPassword(authSvc))
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/api/
git commit -m "feat(api): wire rate limiting for login/register/forgot"
```

---

## Task 8: Login Events Repository

**Files:**
- Create: `internal/repo/loginevent/repo.go`

- [ ] **Step 1: Create login event repo**

```go
package loginevent

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Event mirrors iam.login_events.
type Event struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID     *uuid.UUID `gorm:"type:uuid"`
	AppID      uuid.UUID  `gorm:"type:uuid;not null"`
	Kind       string     `gorm:"not null"`
	IP         string
	UserAgent  string
	OccurredAt time.Time  `gorm:"autoCreateTime"`
}

func (Event) TableName() string { return "login_events" }

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Record inserts a login event. Best-effort — callers should not fail on error.
func (r *Repo) Record(ctx context.Context, appID uuid.UUID, userID *uuid.UUID, kind, ip, userAgent string) error {
	e := &Event{
		UserID:    userID,
		AppID:     appID,
		Kind:      kind,
		IP:        ip,
		UserAgent: userAgent,
	}
	return r.DB.WithContext(ctx).Create(e).Error
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/repo/loginevent/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/repo/loginevent/
git commit -m "feat(repo/loginevent): add login events repository"
```

---

## Task 9: Integrate Login Events in Auth Service

**Files:**
- Modify: `internal/service/auth/auth.go`
- Modify: `cmd/api/main.go`

- [ ] **Step 1: Add LoginEventRepo to Deps**

Update `internal/service/auth/auth.go`:

```go
type Deps struct {
	UserRepo       *userrepo.Repo
	RefreshRepo    *refresh.Repo
	OTP            *otp.Service
	Signer         *pkgauth.Signer
	RefreshTTL     time.Duration
	LoginEventRepo *loginevent.Repo // Add this
}
```

- [ ] **Step 2: Add event recording to Login**

Update `Login` method:

```go
func (s *Service) Login(ctx context.Context, appID uuid.UUID, email, plaintextPassword, audience, ip, userAgent string) (*LoginTokens, error) {
	// ... existing login logic ...
	
	// Record success event (best-effort)
	if s.LoginEventRepo != nil {
		go func() {
			_ = s.LoginEventRepo.Record(context.Background(), appID, &u.ID, "login_success", ip, userAgent)
		}()
	}
	
	return s.issueTokens(ctx, appID, u, audience)
}
```

- [ ] **Step 3: Add event recording to Logout**

Update `Logout` method:

```go
func (s *Service) Logout(ctx context.Context, appID uuid.UUID, userID uuid.UUID, refreshToken, ip, userAgent string) error {
	err := s.RefreshRepo.Revoke(ctx, refreshToken)
	if errors.Is(err, refresh.ErrNotFound) {
		return nil
	}
	
	// Record logout event (best-effort)
	if s.LoginEventRepo != nil {
		go func() {
			_ = s.LoginEventRepo.Record(context.Background(), appID, &userID, "logout", ip, userAgent)
		}()
	}
	
	return err
}
```

- [ ] **Step 4: Wire LoginEventRepo in main.go**

```go
loginEventRepo := loginevent.NewRepo(db)

authSvc := auth.NewService(auth.Deps{
	UserRepo:       userRepo,
	RefreshRepo:    refreshRepo,
	OTP:            otpSvc,
	Signer:         signer,
	RefreshTTL:     cfg.RefreshTTL,
	LoginEventRepo: loginEventRepo,
})
```

- [ ] **Step 5: Verify compilation**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/service/auth/ cmd/api/
git commit -m "feat(auth): integrate login events recording"
```

---

## Task 10: Update HTTP Handlers for Login Events

**Files:**
- Modify: `internal/httpapi/auth.go`

- [ ] **Step 1: Update handleLogin to pass IP and UserAgent**

```go
func handleLogin(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// ... existing code ...
		
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		
		tokens, err := authSvc.Login(c.Request.Context(), app.ID, req.Email, req.Password, app.JWTAudience, ip, ua)
		
		// ... rest of handler ...
	}
}
```

- [ ] **Step 2: Update handleLogout to pass IP and UserAgent**

```go
func handleLogout(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// ... existing code ...
		
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		
		claims, _ := middleware.GetAuthClaims(c)
		var userID uuid.UUID
		if claims != nil {
			userID, _ = uuid.Parse(claims.Subject)
		}
		
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		
		if err := authSvc.Logout(c.Request.Context(), app.ID, userID, req.RefreshToken, ip, ua); err != nil {
			// ... error handling ...
		}
		
		// ... rest of handler ...
	}
}
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/httpapi/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/httpapi/
git commit -m "feat(httpapi): pass IP and UserAgent for login events"
```

---

## Task 11: Final Verification and Tracker Update

**Files:**
- Modify: `docs/migration/tracker.md`

- [ ] **Step 1: Run full test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 2: Run linter**

Run: `go vet ./...`
Expected: PASS

- [ ] **Step 3: Update tracker**

Mark Wave 3 tasks as complete in tracker.

- [ ] **Step 4: Commit**

```bash
git add docs/migration/tracker.md
git commit -m "docs(tracker): mark Wave 3 complete"
```

---

## Exit Criteria Verification

- [ ] `POST /v1/apps/{slug}/auth/password/forgot` sends OTP email
- [ ] `POST /v1/apps/{slug}/auth/password/reset` resets password and revokes tokens
- [ ] Rate limits enforced on login/register/forgot endpoints
- [ ] Login events recorded in `iam.login_events` table
- [ ] `go test ./...` passes
- [ ] `go vet ./...` passes
