package sqlite

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
	row := p.sqliteDb.QueryRow("SELECT "+shareRecipientColumns+" FROM ShareRecipients WHERE email = ?", email)
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
	row := p.sqliteDb.QueryRow("SELECT "+shareRecipientColumns+" FROM ShareRecipients WHERE id = ?", id)
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
		// Creating an address that already exists returns the existing row
		// rather than failing. The service layer looks an address up before
		// creating it, so a duplicate here is a race between two shares naming
		// the same person; raising the UNIQUE violation would panic and take
		// the server down over a case that has an obvious correct answer.
		result, err := p.sqliteDb.Exec(`INSERT OR IGNORE INTO ShareRecipients
			(email, createdat, lastloginat, isblocked) VALUES (?, ?, ?, ?)`,
			recipient.Email, recipient.CreatedAt, recipient.LastLoginAt, recipient.IsBlocked)
		helper.Check(err)
		inserted, err := result.RowsAffected()
		helper.Check(err)
		if inserted == 0 {
			existing, ok := p.GetShareRecipientByEmail(recipient.Email)
			if ok {
				return existing.Id
			}
		}
		newId, err := result.LastInsertId()
		helper.Check(err)
		return int(newId)
	}
	// A plain UPDATE, not INSERT OR REPLACE. REPLACE resolves a UNIQUE(email)
	// conflict by DELETING the row that already holds that address, which would
	// silently destroy a different recipient along with the audit trail of what
	// they were granted. An UPDATE raises the constraint violation instead, so
	// the caller learns the address is taken.
	_, err := p.sqliteDb.Exec(`UPDATE ShareRecipients
		SET email = ?, lastloginat = ?, isblocked = ? WHERE id = ?`,
		recipient.Email, recipient.LastLoginAt, recipient.IsBlocked, recipient.Id)
	helper.Check(err)
	return recipient.Id
}

// GetAllShareRecipients returns every recipient, ordered by email.
func (p DatabaseProvider) GetAllShareRecipients() []models.ShareRecipient {
	result := make([]models.ShareRecipient, 0)
	rows, err := p.sqliteDb.Query("SELECT " + shareRecipientColumns + " FROM ShareRecipients ORDER BY email")
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
	transaction, err := p.sqliteDb.Begin()
	helper.Check(err)
	defer func() { _ = transaction.Rollback() }()
	for _, statement := range []string{
		"DELETE FROM ShareLoginTokens WHERE recipientid = ?",
		"DELETE FROM ShareGrants WHERE recipientid = ?",
		"DELETE FROM ShareRecipients WHERE id = ?",
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
	transaction, err := p.sqliteDb.Begin()
	helper.Check(err)
	defer func() { _ = transaction.Rollback() }()

	_, err = transaction.Exec("DELETE FROM ShareGrants WHERE resourcetype = ? AND resourceid = ?",
		resourceType, resourceId)
	helper.Check(err)

	grantedAt := time.Now().Unix()
	for _, recipientId := range deduplicate(recipientIds) {
		_, err = transaction.Exec(`INSERT OR REPLACE INTO ShareGrants
			(resourcetype, resourceid, recipientid, grantedat, grantedby,
			 downloadsused, downloadsallowed, lastdownloadat) VALUES (?, ?, ?, ?, ?, 0, ?, 0)`,
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
	rows, err := p.sqliteDb.Query("SELECT "+shareGrantColumns+
		" FROM ShareGrants WHERE resourcetype = ? AND resourceid = ? ORDER BY recipientid",
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
	row := p.sqliteDb.QueryRow(`SELECT COUNT(*) FROM ShareGrants g
		INNER JOIN ShareRecipients r ON r.id = g.recipientid
		WHERE g.resourcetype = ? AND g.resourceid = ? AND g.recipientid = ? AND r.isblocked = 0`,
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
	rows, err := p.sqliteDb.Query("SELECT "+shareGrantColumns+
		" FROM ShareGrants WHERE recipientid = ? ORDER BY grantedat DESC", recipientId)
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

// DeleteShareGrants removes every grant on a resource.
func (p DatabaseProvider) DeleteShareGrants(resourceType int, resourceId string) {
	if resourceId == "" {
		return
	}
	_, err := p.sqliteDb.Exec("DELETE FROM ShareGrants WHERE resourcetype = ? AND resourceid = ?",
		resourceType, resourceId)
	helper.Check(err)
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
	result, err := p.sqliteDb.Exec(`UPDATE ShareGrants
		SET downloadsused = downloadsused + 1, lastdownloadat = ?
		WHERE resourcetype = ? AND resourceid = ? AND recipientid = ?
		  AND (downloadsallowed = 0 OR downloadsused < downloadsallowed)`,
		time.Now().Unix(), resourceType, resourceId, recipientId)
	helper.Check(err)
	affected, err := result.RowsAffected()
	helper.Check(err)
	return affected > 0
}

// SaveShareLoginToken stores a magic link.
func (p DatabaseProvider) SaveShareLoginToken(token models.ShareLoginToken) {
	_, err := p.sqliteDb.Exec(`INSERT OR REPLACE INTO ShareLoginTokens
		(tokenhash, recipientid, resourcetype, resourceid, createdat, expiresat,
		 firstusedat, isrevoked, requestedip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
	row := p.sqliteDb.QueryRow(`SELECT tokenhash, recipientid, resourcetype, resourceid,
		createdat, expiresat, firstusedat, isrevoked, requestedip
		FROM ShareLoginTokens WHERE tokenhash = ?`, tokenHash)
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
	_, err := p.sqliteDb.Exec(
		"UPDATE ShareLoginTokens SET firstusedat = ? WHERE tokenhash = ? AND firstusedat = 0",
		usedAt, tokenHash)
	helper.Check(err)
}

// GetLastShareLoginTokenTime returns when the most recent link for this
// recipient and resource was issued, or 0 if there is none.
func (p DatabaseProvider) GetLastShareLoginTokenTime(recipientId int, resourceType int, resourceId string) int64 {
	var createdAt sql.NullInt64
	row := p.sqliteDb.QueryRow(`SELECT MAX(createdat) FROM ShareLoginTokens
		WHERE recipientid = ? AND resourcetype = ? AND resourceid = ?`,
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
	_, err := p.sqliteDb.Exec(`UPDATE ShareLoginTokens SET isrevoked = 1
		WHERE recipientid = ? AND resourcetype = ? AND resourceid = ? AND isrevoked = 0`,
		recipientId, resourceType, resourceId)
	helper.Check(err)
}

// GetAllShareLoginTokens returns every stored link.
func (p DatabaseProvider) GetAllShareLoginTokens() []models.ShareLoginToken {
	result := make([]models.ShareLoginToken, 0)
	rows, err := p.sqliteDb.Query(`SELECT tokenhash, recipientid, resourcetype, resourceid,
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
	_, err := p.sqliteDb.Exec("DELETE FROM ShareLoginTokens WHERE expiresat < ?", now)
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
