package postgres

import (
	"database/sql"
	"errors"
	"math"

	"github.com/forceu/gokapi/internal/helper"
)

const statIdTraffic = "1"
const statIdTrafficSince = "2"

// GetStatTraffic returns the total traffic from statistics
func (p DatabaseProvider) GetStatTraffic() uint64 {
	var result uint64
	row := p.postgresDb.QueryRow("SELECT Value FROM Statistics WHERE Type = $1", statIdTraffic)
	err := row.Scan(&result)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0
		}
		helper.Check(err)
		return 0
	}
	return result
}

// SaveStatTraffic stores the total traffic
func (p DatabaseProvider) SaveStatTraffic(totalTraffic uint64) {
	// Postgres BIGINT is signed, so clamp rather than let pgx reject the value.
	// Only reachable past ~8 EiB of cumulative traffic.
	if totalTraffic > math.MaxInt64 {
		totalTraffic = math.MaxInt64
	}
	_, err := p.postgresDb.Exec(`INSERT INTO Statistics (Type, Value) VALUES ($1, $2)
					ON CONFLICT (Type) DO UPDATE SET Value = EXCLUDED.Value`, statIdTraffic, int64(totalTraffic))
	helper.Check(err)
}

// SaveTrafficSince stores the beginning of traffic counting
func (p DatabaseProvider) SaveTrafficSince(since int64) {
	_, err := p.postgresDb.Exec(`INSERT INTO Statistics (Type, Value) VALUES ($1, $2)
					ON CONFLICT (Type) DO UPDATE SET Value = EXCLUDED.Value`, statIdTrafficSince, since)
	helper.Check(err)
}

// GetTrafficSince gets the beginning of traffic counting
func (p DatabaseProvider) GetTrafficSince() (int64, bool) {
	var result int64
	row := p.postgresDb.QueryRow("SELECT Value FROM Statistics WHERE Type = $1", statIdTrafficSince)
	err := row.Scan(&result)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false
		}
		helper.Check(err)
		return 0, false
	}
	return result, true
}
