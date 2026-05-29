package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	api "github.com/nathan-tsien/iam/api"
	pkgauth "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/config"
	"github.com/nathan-tsien/iam/internal/db"
	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/httpapi"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/ratelimit"
	"github.com/nathan-tsien/iam/internal/ratelimit/memory"
	ratelimitredis "github.com/nathan-tsien/iam/internal/ratelimit/redis"
	auditlogrepo "github.com/nathan-tsien/iam/internal/repo/auditlog"
	apprepo "github.com/nathan-tsien/iam/internal/repo/app"
	logineventrepo "github.com/nathan-tsien/iam/internal/repo/loginevent"
	refreshrepo "github.com/nathan-tsien/iam/internal/repo/refresh"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	authsvc "github.com/nathan-tsien/iam/internal/service/auth"
	"github.com/nathan-tsien/iam/internal/service/otp"
	useradminsvc "github.com/nathan-tsien/iam/internal/service/useradmin"
	userprofilesvc "github.com/nathan-tsien/iam/internal/service/userprofile"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	gormDB, err := db.Open(cfg.DatabaseURL, cfg.DatabaseSchema, cfg.AppEnv)
	if err != nil {
		slog.Error("connect database", "error", err)
		os.Exit(1)
	}

	if cfg.AppEnv != "development" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	httpapi.RegisterHealth(router, gormDB)

	// --- Auth wiring ---
	userRepo := userrepo.NewRepo(gormDB)
	refreshRepo := refreshrepo.NewRepo(gormDB)
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
			slog.Error("init smtp mailer", "error", err)
			os.Exit(1)
		}
	} else {
		mailer = &mail.LogMailer{}
	}
	otpSvc := otp.NewService(gormDB, mailer, 10*time.Minute)
	signer := pkgauth.NewSigner(cfg.JWTSecret, cfg.JWTTTL)
	loginEventRepo := logineventrepo.NewRepo(gormDB)
	authSvc := authsvc.NewService(authsvc.Deps{
		UserRepo:       userRepo,
		RefreshRepo:    refreshRepo,
		OTP:            otpSvc,
		Signer:         signer,
		RefreshTTL:     cfg.RefreshTTL,
		LoginEventRepo: loginEventRepo,
	})

	// --- Rate limiting ---
	var rlStore ratelimit.Store
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Error("parse redis url", "error", err)
			os.Exit(1)
		}
		redisClient := redis.NewClient(opt)
		rlStore = ratelimitredis.NewStore(redisClient)
	} else {
		rlStore = memory.NewStore()
	}

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

	// --- Strict server ---
	strictServer := &httpapi.StrictServer{
		AuthSvc:    authSvc,
		ProfileSvc: profileSvc,
		AdminSvc:   adminSvc,
	}

	middlewares := []api.StrictMiddlewareFunc{
		httpapi.StrictRateLimitMiddleware(rlStore),
		httpapi.StrictAuthMiddleware(signer),
		httpapi.StrictAdminMiddleware(userRepo),
	}

	strictHandler := api.NewStrictHandlerWithOptions(strictServer, middlewares, api.StrictGinServerOptions{
		RequestErrorHandlerFunc: func(c *gin.Context, err error) {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
		},
		HandlerErrorFunc: func(c *gin.Context, err error) {
			var appErr *httpapi.AppError
			if errors.As(err, &appErr) {
				errs.Render(c, errs.New(appErr.Status, appErr.Code, appErr.Message))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
		},
	})

	api.RegisterHandlers(v1, strictHandler)

	// --- Server ---
	addr := fmt.Sprintf(":%d", cfg.AppPort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("api server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown", "error", err)
	}
}
