package mail

import (
	"context"
	"log/slog"
)

// LogMailer is a development mailer that logs OTP codes to stdout
// instead of sending real emails. Used until Wave 3 adds SMTP support.
type LogMailer struct{}

func (m *LogMailer) SendOTP(_ context.Context, email, code string, purpose Purpose, locale Locale) error {
	slog.Info("OTP email (dev mode)",
		"email", email,
		"code", code,
		"purpose", string(purpose),
		"locale", string(locale),
	)
	return nil
}
