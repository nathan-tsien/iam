package passwordpolicy

import (
	"sort"
	"unicode"
)

const (
	MinLength       = 8
	MaxLength       = 128
	MaxBytes        = 72
	RequiredClasses = 3
)

const (
	RuleMinLength             = "min_length"
	RuleMaxLength             = "max_length"
	RuleMaxBytes              = "max_bytes"
	RuleCharClasses           = "char_classes"
	RuleSurroundingWhitespace = "surrounding_whitespace"
)

func Validate(pw string) []string {
	var fails []string

	runes := []rune(pw)
	if len(runes) < MinLength {
		fails = append(fails, RuleMinLength)
	}
	if len(runes) > MaxLength {
		fails = append(fails, RuleMaxLength)
	}
	if len(pw) > MaxBytes {
		fails = append(fails, RuleMaxBytes)
	}

	var upper, lower, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{upper, lower, digit, other} {
		if ok {
			classes++
		}
	}
	if classes < RequiredClasses {
		fails = append(fails, RuleCharClasses)
	}

	if len(runes) > 0 {
		if unicode.IsSpace(runes[0]) || unicode.IsSpace(runes[len(runes)-1]) {
			fails = append(fails, RuleSurroundingWhitespace)
		}
	}

	if len(fails) == 0 {
		return nil
	}
	sort.Strings(fails)
	return fails
}
