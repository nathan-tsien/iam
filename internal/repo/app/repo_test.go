package app

import "testing"

func TestValidateSlug(t *testing.T) {
	tests := []struct {
		slug    string
		wantErr bool
	}{
		{"demo", false},
		{"my-product", false},
		{"_iam", true},
		{"Bad", true},
		{"a", true},
		{"", true},
	}

	for _, tc := range tests {
		err := ValidateSlug(tc.slug)
		if tc.wantErr && err == nil {
			t.Fatalf("ValidateSlug(%q) expected error", tc.slug)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("ValidateSlug(%q): %v", tc.slug, err)
		}
	}
}
