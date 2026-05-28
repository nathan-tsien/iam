package mail

import (
	"context"
	"strings"
)

// Locale is a BCP-47 language tag limited to the supported set.
type Locale string

const (
	LocaleZhCN Locale = "zh-CN"
	LocaleZhTW Locale = "zh-TW"
	LocaleEnUS Locale = "en-US"
)

// Normalize converts an arbitrary locale string into the nearest
// supported Locale. The default is zh-CN.
func Normalize(s string) Locale {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return LocaleZhCN
	}
	if strings.HasPrefix(lower, "zh") {
		for _, sub := range strings.Split(lower, "-")[1:] {
			switch sub {
			case "tw", "hk", "mo", "hant":
				return LocaleZhTW
			}
		}
		return LocaleZhCN
	}
	if strings.HasPrefix(lower, "en") {
		return LocaleEnUS
	}
	return LocaleZhCN
}

// context helpers -------------------------------------------------------

type localeKey struct{}

// WithLocale stores a Locale in ctx.
func WithLocale(ctx context.Context, loc Locale) context.Context {
	return context.WithValue(ctx, localeKey{}, loc)
}

// LocaleFrom retrieves the Locale stored in ctx, falling back to zh-CN.
func LocaleFrom(ctx context.Context) Locale {
	if ctx == nil {
		return LocaleZhCN
	}
	if v, ok := ctx.Value(localeKey{}).(Locale); ok {
		return v
	}
	return LocaleZhCN
}
