package mail

import "context"

// Purpose identifies why an OTP is being sent.
type Purpose string

const (
	PurposeRegister      Purpose = "register"
	PurposePasswordReset Purpose = "password_reset"
)

// Mailer abstracts sending OTP emails so the service layer
// never depends on a concrete SMTP implementation.
type Mailer interface {
	SendOTP(ctx context.Context, email, code string, purpose Purpose, locale Locale) error
}
