package postgres

import (
	"database/sql"
	"errors"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

// ---------------------------------------------------------------------------
// Recipients
// ---------------------------------------------------------------------------

const shareRecipientColumns = "id, email, createdat, lastloginat, isblocked"

func scanShareRecipient(scanner interface{ Scan(...any) error }) (models.ShareRecipient, error) {
	var result models.ShareRecipient
	err := scanner.Scan(&result.Id, &result.Email, &result.CreatedAt, &result.LastLoginAt, &result.IsBlocked)
	return result, err
}

// GetShareRecipientByEmail returns the recipient with this email, or false.
func (p DatabaseProvider) GetShareRecipientByEmail(email string) (models.ShareRecipient, bool) {
	if email == "" {
		return models.ShareRecipient{}, false
	}
	row := p.queryRow("SELECT "+shareRecipientColumns+" FROM ShareRecipients WHERE email = $1", email)
	result, err := scanShareRecipient(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ShareRecipient{}, false
		}
		helper.Check(err)
	}
	return result, true
}

// GetShareRecipient returns the recipient with this ID, or false.
func (p DatabaseProvider) GetShareRecipient(id int) (models.ShareRecipient, bool) {
	row := p.queryRow("SELECT "+shareRecipientColumns+" FROM ShareRecipients WHERE id = $1", id)
	result, err := scanShareRecipient(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ShareRecipient{}, false
		}
		helper.Check(err)
	}
	return result, true
}

// SaveShareRecipient stores a recipient, returning the row's ID.
func (p DatabaseProvider) SaveShareRecipient(recipient models.ShareRecipient) int {
	if recipient.Id == 0 {
		// Postgres has no LastInsertId, so the assigned key comes back via
		// RETURNING. DO NOTHING makes creating an existing address return that
		// row instead of raising the UNIQUE violation, matching SQLite and
		// Redis: the service layer looks an address up first, so a duplicate
		// here is a race with an obvious correct answer rather than an error.
		var newId int
		row := p.queryRow(`INSERT INTO ShareRecipients
			(email, createdat, lastloginat, isblocked) VALUES ($1, $2, $3, $4)
			ON CONFLICT (email) DO NOTHING RETURNING id`,
			recipient.Email, recipient.CreatedAt, recipient.LastLoginAt, recipient.IsBlocked)
		err := row.Scan(&newId)
		if errors.Is(err, sql.ErrNoRows) {
			existing, ok := p.GetShareRecipientByEmail(recipient.Email)
			if ok {
				return existing.Id
			}
		}
		helper.Check(err)
		return newId
	}
	// A plain UPDATE, matching SQLite. An upsert keyed on id would still hit
	// the UNIQUE(email) constraint when the address belongs to someone else,
	// and inserting an explicit id would leave the SERIAL sequence behind,
	// making a later id=0 insert collide.
	_, err := p.exec(`UPDATE ShareRecipients
		SET email = $1, lastloginat = $2, isblocked = $3 WHERE id = $4`,
		recipient.Email, recipient.LastLoginAt, recipient.IsBlocked, recipient.Id)
	helper.Check(err)
	return recipient.Id
}

// GetAllShareRecipients returns every recipient, ordered by email.
func (p DatabaseProvider) GetAllShareRecipients() []models.ShareRecipient {
	result := make([]models.ShareRecipient, 0)
	rows, err := p.query("SELECT " + shareRecipientColumns + " FROM ShareRecipients ORDER BY email")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		recipient, err := scanShareRecipient(rows)
		helper.Check(err)
		result = append(result, recipient)
	}
	helper.Check(rows.Err())
	return result
}

// DeleteShareRecipient removes a recipient and everything that points at them.
//
// All three deletes run in one transaction. A partial delete would leave grants
// or an unexpired session belonging to an account that no longer exists, and a
// future recipient issued the same ID would inherit them.
func (p DatabaseProvider) DeleteShareRecipient(id int) {
	transaction, err := p.postgresDb.Begin()
	helper.Check(err)
	defer func() { _ = transaction.Rollback() }()
	for _, statement := range []string{
		"DELETE FROM ShareLoginTokens WHERE recipientid = $1",
		"DELETE FROM ShareGrants WHERE recipientid = $1",
		"DELETE FROM ShareRecipients WHERE id = $1",
	} {
		_, err = transaction.Exec(statement, id)
		helper.Check(err)
	}
	helper.Check(transaction.Commit())
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

const shareGrantColumns = "resourcetype, resourceid, recipientid, grantedat, grantedby, downloadsused, downloadsallowed, lastdownloadat"

func scanShareGrant(scanner interface{ Scan(...any) error }) (models.ShareGrant, error) {
	var result models.ShareGrant
	err := scanner.Scan(&result.ResourceType, &result.ResourceId, &result.RecipientId,
		&result.GrantedAt, &result.GrantedBy, &result.DownloadsUsed,
		&result.DownloadsAllowed, &result.LastDownloadAt)
	return result, err
}

// SetShareGrants replaces the recipient list for one resource.
//
// The delete and the inserts run in one transaction. Without it, a failure
// between them would leave the resource with no grants at all, which is a
// silent downgrade from identity-gated to anonymously reachable. Failing
// closed on the previous list is the safe direction.
func (p DatabaseProvider) SetShareGrants(resourceType int, resourceId string, recipientIds []int, grantedBy int, downloadsAllowed int) {
	if resourceId == "" || !models.IsValidShareResourceType(resourceType) {
		return
	}
	transaction, err := p.postgresDb.Begin()
	helper.Check(err)
	defer func() { _ = transaction.Rollback() }()

	_, err = transaction.Exec("DELETE FROM ShareGrants WHERE resourcetype = $1 AND resourceid = $2",
		resourceType, resourceId)
	helper.Check(err)

	grantedAt := time.Now().Unix()
	for _, recipientId := range deduplicate(recipientIds) {
		_, err = transaction.Exec(`INSERT INTO ShareGrants
			(resourcetype, resourceid, recipientid, grantedat, grantedby,
			 downloadsused, downloadsallowed, lastdownloadat) VALUES ($1, $2, $3, $4, $5, 0, $6, 0)
			ON CONFLICT (resourcetype, resourceid, recipientid) DO UPDATE
			SET grantedat = EXCLUDED.grantedat, grantedby = EXCLUDED.grantedby,
				downloadsallowed = EXCLUDED.downloadsallowed`,
			resourceType, resourceId, recipientId, grantedAt, grantedBy, downloadsAllowed)
		helper.Check(err)
	}
	helper.Check(transaction.Commit())
}

// GetShareGrants returns every grant on a resource.
func (p DatabaseProvider) GetShareGrants(resourceType int, resourceId string) []models.ShareGrant {
	result := make([]models.ShareGrant, 0)
	if resourceId == "" {
		return result
	}
	rows, err := p.query("SELECT "+shareGrantColumns+
		" FROM ShareGrants WHERE resourcetype = $1 AND resourceid = $2 ORDER BY recipientid",
		resourceType, resourceId)
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		grant, err := scanShareGrant(rows)
		helper.Check(err)
		result = append(result, grant)
	}
	helper.Check(rows.Err())
	return result
}

// HasShareGrant reports whether this recipient may reach this resource. The
// recipient must also not be blocked: blocking is meant to take effect at
// once, without hunting down existing grants or live sessions.
func (p DatabaseProvider) HasShareGrant(resourceType int, resourceId string, recipientId int) bool {
	if resourceId == "" {
		return false
	}
	var count int
	row := p.queryRow(`SELECT COUNT(*) FROM ShareGrants g
		INNER JOIN ShareRecipients r ON r.id = g.recipientid
		WHERE g.resourcetype = $1 AND g.resourceid = $2 AND g.recipientid = $3 AND r.isblocked = false`,
		resourceType, resourceId, recipientId)
	err := row.Scan(&count)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		helper.Check(err)
	}
	return count > 0
}

// GetShareGrantsForRecipient returns every grant the recipient holds.
func (p DatabaseProvider) GetShareGrantsForRecipient(recipientId int) []models.ShareGrant {
	result := make([]models.ShareGrant, 0)
	rows, err := p.query("SELECT "+shareGrantColumns+
		" FROM ShareGrants WHERE recipientid = $1 ORDER BY grantedat DESC", recipientId)
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		grant, err := scanShareGrant(rows)
		helper.Check(err)
		result = append(result, grant)
	}
	helper.Check(rows.Err())
	return result
}

// DeleteShareGrants removes every grant on a resource, and every login token
// issued against it: once the grant is gone a leftover token would still let
// its holder in, so the two must go together. Runs in one transaction so a
// failure between them cannot leave a token alive with no grant behind it.
func (p DatabaseProvider) DeleteShareGrants(resourceType int, resourceId string) {
	if resourceId == "" {
		return
	}
	transaction, err := p.postgresDb.Begin()
	helper.Check(err)
	defer func() { _ = transaction.Rollback() }()

	_, err = transaction.Exec("DELETE FROM ShareGrants WHERE resourcetype = $1 AND resourceid = $2",
		resourceType, resourceId)
	helper.Check(err)

	_, err = transaction.Exec("DELETE FROM ShareLoginTokens WHERE resourcetype = $1 AND resourceid = $2",
		resourceType, resourceId)
	helper.Check(err)

	helper.Check(transaction.Commit())
}

// ---------------------------------------------------------------------------
// Login tokens and sessions
// ---------------------------------------------------------------------------

// IncreaseShareGrantDownloadCount atomically records one download.
//
// The allowance test lives in the UPDATE's WHERE clause, mirroring
// IncreaseDownloadCount in metadata.go. Reading the count and then writing it
// back would let two concurrent downloads both observe one remaining and both
// proceed. A downloadsallowed of 0 means unlimited.
func (p DatabaseProvider) IncreaseShareGrantDownloadCount(resourceType int, resourceId string, recipientId int) bool {
	result, err := p.exec(`UPDATE ShareGrants
		SET downloadsused = downloadsused + 1, lastdownloadat = $1
		WHERE resourcetype = $2 AND resourceid = $3 AND recipientid = $4
		  AND (downloadsallowed = 0 OR downloadsused < downloadsallowed)`,
		time.Now().Unix(), resourceType, resourceId, recipientId)
	helper.Check(err)
	affected, err := result.RowsAffected()
	helper.Check(err)
	return affected > 0
}

// SaveShareLoginToken stores a magic link.
func (p DatabaseProvider) SaveShareLoginToken(token models.ShareLoginToken) {
	_, err := p.exec(`INSERT INTO ShareLoginTokens
		(tokenhash, recipientid, resourcetype, resourceid, createdat, expiresat,
		 firstusedat, isrevoked, requestedip) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tokenhash) DO NOTHING`,
		token.TokenHash, token.RecipientId, token.ResourceType, token.ResourceId,
		token.CreatedAt, token.ExpiresAt, token.FirstUsedAt, token.IsRevoked, token.RequestedIp)
	helper.Check(err)
}

// GetShareLoginToken returns the token with this hash, or false.
func (p DatabaseProvider) GetShareLoginToken(tokenHash string) (models.ShareLoginToken, bool) {
	if tokenHash == "" {
		return models.ShareLoginToken{}, false
	}
	var result models.ShareLoginToken
	row := p.queryRow(`SELECT tokenhash, recipientid, resourcetype, resourceid,
		createdat, expiresat, firstusedat, isrevoked, requestedip
		FROM ShareLoginTokens WHERE tokenhash = $1`, tokenHash)
	err := row.Scan(&result.TokenHash, &result.RecipientId, &result.ResourceType,
		&result.ResourceId, &result.CreatedAt, &result.ExpiresAt, &result.FirstUsedAt,
		&result.IsRevoked, &result.RequestedIp)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ShareLoginToken{}, false
		}
		helper.Check(err)
	}
	return result, true
}

// MarkShareLoginTokenUsed records the first redemption, for audit only.
//
// The firstusedat = 0 guard makes this record the FIRST use rather than the
// most recent one, so the audit trail shows when the link was actually
// collected. The link stays usable regardless: it is reusable by design.
func (p DatabaseProvider) MarkShareLoginTokenUsed(tokenHash string, usedAt int64) {
	_, err := p.exec(
		"UPDATE ShareLoginTokens SET firstusedat = $1 WHERE tokenhash = $2 AND firstusedat = 0",
		usedAt, tokenHash)
	helper.Check(err)
}

// GetLastShareLoginTokenTime returns when the most recent link for this
// recipient and resource was issued, or 0 if there is none.
func (p DatabaseProvider) GetLastShareLoginTokenTime(recipientId int, resourceType int, resourceId string) int64 {
	var createdAt sql.NullInt64
	row := p.queryRow(`SELECT MAX(createdat) FROM ShareLoginTokens
		WHERE recipientid = $1 AND resourcetype = $2 AND resourceid = $3`,
		recipientId, resourceType, resourceId)
	err := row.Scan(&createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0
		}
		helper.Check(err)
	}
	if !createdAt.Valid {
		return 0
	}
	return createdAt.Int64
}

// RevokeShareLoginTokens retires every live link for this recipient and
// resource, so a link sitting in an older mail stops working the moment a
// replacement is issued. Without it, every resend would leave another live
// bearer credential in an inbox.
func (p DatabaseProvider) RevokeShareLoginTokens(recipientId int, resourceType int, resourceId string) {
	_, err := p.exec(`UPDATE ShareLoginTokens SET isrevoked = true
		WHERE recipientid = $1 AND resourcetype = $2 AND resourceid = $3 AND isrevoked = false`,
		recipientId, resourceType, resourceId)
	helper.Check(err)
}

// GetAllShareLoginTokens returns every stored link.
func (p DatabaseProvider) GetAllShareLoginTokens() []models.ShareLoginToken {
	result := make([]models.ShareLoginToken, 0)
	rows, err := p.query(`SELECT tokenhash, recipientid, resourcetype, resourceid,
		createdat, expiresat, firstusedat, isrevoked, requestedip FROM ShareLoginTokens`)
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		var token models.ShareLoginToken
		helper.Check(rows.Scan(&token.TokenHash, &token.RecipientId, &token.ResourceType,
			&token.ResourceId, &token.CreatedAt, &token.ExpiresAt, &token.FirstUsedAt,
			&token.IsRevoked, &token.RequestedIp))
		result = append(result, token)
	}
	helper.Check(rows.Err())
	return result
}

// CleanUpExpiredShareLoginTokens removes links that have expired.
func (p DatabaseProvider) CleanUpExpiredShareLoginTokens(now int64) {
	_, err := p.exec("DELETE FROM ShareLoginTokens WHERE expiresat < $1", now)
	helper.Check(err)
}

// deduplicate removes repeated IDs while preserving order. Resolving an email
// list can legitimately produce duplicates, for example when two spellings of
// an address normalise to the same recipient.
func deduplicate(ids []int) []int {
	seen := make(map[int]bool, len(ids))
	result := make([]int, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, id)
	}
	return result
}
