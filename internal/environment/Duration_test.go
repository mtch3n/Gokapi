package environment

import (
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/test"
)

func TestDurationUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"Day", "1d", 24 * time.Hour, false},
		{"MultiDay", "30d", 30 * 24 * time.Hour, false},
		{"Week", "2w", 2 * 7 * 24 * time.Hour, false},
		{"Hour", "1h", time.Hour, false},
		{"Minutes", "90m", 90 * time.Minute, false},
		{"CombinedNative", "1h30m", time.Hour + 30*time.Minute, false},
		{"Zero", "0", 0, false},
		{"BadInput", "bogus", 0, true},
		{"BadDaySuffix", "xd", 0, true},
		{"Year", "1y", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got none", tc.input)
				}
				return
			}
			test.IsNil(t, err)
			test.IsEqualInt64(t, int64(d), int64(tc.want))
		})
	}
}

func TestNormalizeExpiryOptions(t *testing.T) {
	t.Run("DedupeAndSort", func(t *testing.T) {
		env := Environment{
			MaxExpiry: 0,
			ExpiryOptions: []Duration{
				Duration(7 * 24 * time.Hour),
				Duration(time.Hour),
				Duration(7 * 24 * time.Hour),
				Duration(24 * time.Hour),
			},
		}
		normalizeExpiryOptions(&env)
		want := []Duration{Duration(time.Hour), Duration(24 * time.Hour), Duration(7 * 24 * time.Hour)}
		if len(env.ExpiryOptions) != len(want) {
			t.Fatalf("got %v, want %v", env.ExpiryOptions, want)
		}
		for i := range want {
			test.IsEqualInt64(t, int64(env.ExpiryOptions[i]), int64(want[i]))
		}
	})

	t.Run("DropsNonPositive", func(t *testing.T) {
		env := Environment{
			ExpiryOptions: []Duration{Duration(-time.Hour), 0, Duration(time.Hour)},
		}
		normalizeExpiryOptions(&env)
		test.IsEqualInt(t, len(env.ExpiryOptions), 1)
		test.IsEqualInt64(t, int64(env.ExpiryOptions[0]), int64(time.Hour))
	})

	t.Run("DropsAboveMax", func(t *testing.T) {
		env := Environment{
			MaxExpiry: Duration(7 * 24 * time.Hour),
			ExpiryOptions: []Duration{
				Duration(time.Hour),
				Duration(7 * 24 * time.Hour),
				Duration(30 * 24 * time.Hour),
			},
		}
		normalizeExpiryOptions(&env)
		want := []Duration{Duration(time.Hour), Duration(7 * 24 * time.Hour)}
		if len(env.ExpiryOptions) != len(want) {
			t.Fatalf("got %v, want %v", env.ExpiryOptions, want)
		}
	})

	t.Run("EmptyFallsBackToDefault", func(t *testing.T) {
		env := Environment{
			MaxExpiry:     Duration(time.Minute),
			ExpiryOptions: []Duration{Duration(time.Hour), Duration(24 * time.Hour)},
		}
		normalizeExpiryOptions(&env)
		if len(env.ExpiryOptions) != len(defaultExpiryOptions) {
			t.Fatalf("got %v, want fallback to default list %v", env.ExpiryOptions, defaultExpiryOptions)
		}
		for i := range defaultExpiryOptions {
			test.IsEqualInt64(t, int64(env.ExpiryOptions[i]), int64(defaultExpiryOptions[i]))
		}
	})
}
