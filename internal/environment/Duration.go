package environment

import (
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that additionally accepts a trailing "d" (day) or "w" (week)
// unit, which time.ParseDuration does not support - it stops at "h". A year is deliberately
// not supported: a year is 365 or 365.25 days depending who is asking, while "365d" is
// unambiguous. Every other unit, including "h", is delegated to time.ParseDuration unchanged.
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler, so github.com/caarlos0/env/v6 picks this
// type up automatically, including for slices via envSeparator.
func (d *Duration) UnmarshalText(text []byte) error {
	s := string(text)
	unit := 24 * time.Hour
	suffix := "d"
	if strings.HasSuffix(s, "w") {
		unit = 7 * 24 * time.Hour
		suffix = "w"
	} else if !strings.HasSuffix(s, "d") {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	value, err := strconv.ParseFloat(strings.TrimSuffix(s, suffix), 64)
	if err != nil {
		return err
	}
	*d = Duration(value * float64(unit))
	return nil
}
