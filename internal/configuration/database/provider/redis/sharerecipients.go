package redis

import (
	"sort"
	"strconv"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	redigo "github.com/gomodule/redigo/redis"
)

const (
	prefixShareRecipient      = "shrc:"
	prefixShareRecipientEmail = "shre:"
	keyShareRecipientNextId   = "shrcnext"
	prefixShareGrant          = "shg:"
	prefixShareGrantByUser    = "shgr:"
	prefixShareLoginToken     = "shlt:"
)

// grantKey builds the composite key for one grant. The resource type is part
// of the key so that a file and a bundle sharing an ID can never collide.
func grantKey(resourceType int, resourceId string, recipientId int) string {
	return strconv.Itoa(resourceType) + ":" + resourceId + ":" + strconv.Itoa(recipientId)
}

func resourcePrefix(resourceType int, resourceId string) string {
	return strconv.Itoa(resourceType) + ":" + resourceId + ":"
}

// ---------------------------------------------------------------------------
// Recipients
// ---------------------------------------------------------------------------

// GetShareRecipientByEmail returns the recipient with this email, or false.
// The email index is a separate key rather than a scan over every recipient,
// because this lookup runs on the request path each time a link is requested.
func (p DatabaseProvider) GetShareRecipientByEmail(email string) (models.ShareRecipient, bool) {
	if email == "" {
		return models.ShareRecipient{}, false
	}
	id, ok := p.getKeyInt(prefixShareRecipientEmail + email)
	if !ok {
		return models.ShareRecipient{}, false
	}
	return p.GetShareRecipient(id)
}

// GetShareRecipient returns the recipient with this ID, or false.
func (p DatabaseProvider) GetShareRecipient(id int) (models.ShareRecipient, bool) {
	values, ok := p.getHashMap(prefixShareRecipient + strconv.Itoa(id))
	if !ok {
		return models.ShareRecipient{}, false
	}
	var result models.ShareRecipient
	helper.Check(redigo.ScanStruct(values, &result))
	return result, true
}

// SaveShareRecipient stores a recipient, returning the row's ID.
func (p DatabaseProvider) SaveShareRecipient(recipient models.ShareRecipient) int {
	if recipient.Id == 0 {
		// The SQL providers get uniqueness from a UNIQUE(email) constraint.
		// Redis has none, so two concurrent creations of the same address would
		// otherwise produce two recipient hashes that merely overwrite each
		// other's index entry, leaving an orphan whose grants nothing can
		// reach. SETNX claims the address atomically; losing the race means
		// someone else created it, so that row is used instead.
		conn := p.pool.Get()
		defer conn.Close()
		newId, err := redigo.Int(conn.Do("INCR", p.dbPrefix+keyShareRecipientNextId))
		helper.Check(err)
		claimed, err := redigo.Int(conn.Do("SETNX", p.dbPrefix+prefixShareRecipientEmail+recipient.Email, newId))
		helper.Check(err)
		if claimed == 0 {
			existingId, err := redigo.Int(conn.Do("GET", p.dbPrefix+prefixShareRecipientEmail+recipient.Email))
			helper.Check(err)
			return existingId
		}
		recipient.Id = newId
		p.setHashMap(p.buildArgs(prefixShareRecipient + strconv.Itoa(recipient.Id)).AddFlat(recipient))
		return recipient.Id
	}
	if previous, ok := p.GetShareRecipient(recipient.Id); ok && previous.Email != recipient.Email {
		// Drop the index entry for the old address. Without this the previous
		// email keeps resolving to this recipient forever, so a renamed
		// contact would still be reachable, and grantable, under an address
		// they no longer own. The SQL providers update the column in place and
		// have no equivalent hazard.
		p.deleteKey(prefixShareRecipientEmail + previous.Email)
	}
	p.setHashMap(p.buildArgs(prefixShareRecipient + strconv.Itoa(recipient.Id)).AddFlat(recipient))
	p.setKey(prefixShareRecipientEmail+recipient.Email, recipient.Id)
	return recipient.Id
}

// GetAllShareRecipients returns every recipient, ordered by email.
func (p DatabaseProvider) GetAllShareRecipients() []models.ShareRecipient {
	result := make([]models.ShareRecipient, 0)
	for _, values := range p.getAllHashesWithPrefix(prefixShareRecipient) {
		var recipient models.ShareRecipient
		helper.Check(redigo.ScanStruct(values, &recipient))
		result = append(result, recipient)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Email < result[j].Email })
	return result
}

// DeleteShareRecipient removes a recipient and everything that points at them.
//
// Every delete goes into one MULTI/EXEC, matching the transaction the SQL
// providers use. A partial delete would leave grants or an unexpired link
// belonging to an account that no longer exists, and a future recipient handed
// the same ID would inherit them.
func (p DatabaseProvider) DeleteShareRecipient(id int) {
	recipient, recipientExists := p.GetShareRecipient(id)
	grants := p.GetShareGrantsForRecipient(id)
	tokens := p.allShareLoginTokens()

	conn := p.pool.Get()
	defer conn.Close()
	helper.Check(conn.Send("MULTI"))
	if recipientExists {
		helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareRecipientEmail+recipient.Email))
	}
	for _, grant := range grants {
		helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareGrant+
			grantKey(grant.ResourceType, grant.ResourceId, id)))
	}
	helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareGrantByUser+strconv.Itoa(id)))
	for _, token := range tokens {
		if token.RecipientId == id {
			helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareLoginToken+token.TokenHash))
		}
	}
	helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareRecipient+strconv.Itoa(id)))
	_, err := conn.Do("EXEC")
	helper.Check(err)
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

// SetShareGrants brings the recipient list for one resource into line with the
// list given. Recipients that are new get a grant, recipients that are gone
// lose theirs, and recipients that appear in both are left alone.
//
// Left alone means untouched, not rewritten with the same values. Re-issuing a
// grant that already exists would set DownloadsUsed back to zero, which refunds
// a recipient who had already spent their allowance and brings a resource every
// recipient had finished with back within reach; it would set LastDownloadAt
// back to zero, which makes the owner's list claim a file was never opened by
// someone who collected it; and it would overwrite DownloadsAllowed with
// whatever the resource's limit happens to be now. Adding a fourth address to a
// share is not a reason for any of that to happen to the first three.
//
// A recipient that stays is skipped in both loops, so neither their shg: hash
// nor their shgr: index entry is written. The index entry records GrantedAt,
// which must not move either.
func (p DatabaseProvider) SetShareGrants(resourceType int, resourceId string, recipientIds []int, grantedBy int, downloadsAllowed int) {
	if resourceId == "" || !models.IsValidShareResourceType(resourceType) {
		return
	}
	previous := p.GetShareGrants(resourceType, resourceId)
	wanted := deduplicate(recipientIds)
	existing := make([]int, 0, len(previous))
	for _, grant := range previous {
		existing = append(existing, grant.RecipientId)
	}
	grantedAt := time.Now().Unix()

	// The new grants are written BEFORE the old ones are removed, and the whole
	// thing runs as one MULTI/EXEC.
	//
	// Order matters here in a way it does not for the SQL providers, which get
	// a real transaction. Deleting first would leave a window in which the
	// resource has no grants at all, and a resource with no grants reads as
	// unrestricted: IsShareRestricted returns false, AccessMode returns
	// "public", and the file is briefly downloadable by anyone with the link.
	// Failing towards the previous, stricter list is the safe direction.
	conn := p.pool.Get()
	defer conn.Close()
	helper.Check(conn.Send("MULTI"))

	for _, recipientId := range wanted {
		if containsInt(existing, recipientId) {
			continue
		}
		grant := models.ShareGrant{
			ResourceType:     resourceType,
			ResourceId:       resourceId,
			RecipientId:      recipientId,
			GrantedAt:        grantedAt,
			GrantedBy:        grantedBy,
			DownloadsAllowed: downloadsAllowed,
		}
		key := grantKey(resourceType, resourceId, recipientId)
		helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareGrant+key))
		helper.Check(conn.Send("HSET", redigo.Args{}.Add(p.dbPrefix+prefixShareGrant+key).AddFlat(grant)...))
		helper.Check(conn.Send("HSET", p.dbPrefix+prefixShareGrantByUser+strconv.Itoa(recipientId),
			key, grantedAt))
	}
	for _, existingGrant := range previous {
		if containsInt(wanted, existingGrant.RecipientId) {
			continue
		}
		key := grantKey(resourceType, resourceId, existingGrant.RecipientId)
		helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareGrant+key))
		helper.Check(conn.Send("HDEL", p.dbPrefix+prefixShareGrantByUser+strconv.Itoa(existingGrant.RecipientId), key))
	}
	_, err := conn.Do("EXEC")
	helper.Check(err)
}

// containsInt reports whether this ID is in the list.
func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// GetShareGrants returns every grant on a resource.
func (p DatabaseProvider) GetShareGrants(resourceType int, resourceId string) []models.ShareGrant {
	result := make([]models.ShareGrant, 0)
	if resourceId == "" {
		return result
	}
	for _, values := range p.getAllHashesWithPrefix(prefixShareGrant + resourcePrefix(resourceType, resourceId)) {
		var grant models.ShareGrant
		helper.Check(redigo.ScanStruct(values, &grant))
		result = append(result, grant)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RecipientId < result[j].RecipientId })
	return result
}

// GetAllShareGrants returns every grant in the database, ordered by resource then recipient.
func (p DatabaseProvider) GetAllShareGrants() []models.ShareGrant {
	result := make([]models.ShareGrant, 0)
	for _, values := range p.getAllHashesWithPrefix(prefixShareGrant) {
		var grant models.ShareGrant
		helper.Check(redigo.ScanStruct(values, &grant))
		result = append(result, grant)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ResourceType != result[j].ResourceType {
			return result[i].ResourceType < result[j].ResourceType
		}
		if result[i].ResourceId != result[j].ResourceId {
			return result[i].ResourceId < result[j].ResourceId
		}
		return result[i].RecipientId < result[j].RecipientId
	})
	return result
}

// HasShareGrant reports whether this recipient may reach this resource. A
// blocked recipient is refused even while the grant row survives, so that
// blocking takes effect immediately.
func (p DatabaseProvider) HasShareGrant(resourceType int, resourceId string, recipientId int) bool {
	if resourceId == "" {
		return false
	}
	if _, ok := p.getHashMap(prefixShareGrant + grantKey(resourceType, resourceId, recipientId)); !ok {
		return false
	}
	recipient, ok := p.GetShareRecipient(recipientId)
	if !ok || recipient.IsBlocked {
		return false
	}
	return true
}

// GetShareGrantsForRecipient returns every grant the recipient holds.
func (p DatabaseProvider) GetShareGrantsForRecipient(recipientId int) []models.ShareGrant {
	result := make([]models.ShareGrant, 0)
	fields, ok := p.getHashMap(prefixShareGrantByUser + strconv.Itoa(recipientId))
	if !ok {
		return result
	}
	keys, err := redigo.Int64Map(fields, nil)
	helper.Check(err)
	for key := range keys {
		values, found := p.getHashMap(prefixShareGrant + key)
		if !found {
			continue
		}
		var grant models.ShareGrant
		helper.Check(redigo.ScanStruct(values, &grant))
		result = append(result, grant)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GrantedAt > result[j].GrantedAt })
	return result
}

// DeleteShareGrants removes every grant on a resource, and every login token
// issued against it: once the grant is gone a leftover token would still let
// its holder in, so the two must go together. Redis has no resource index for
// tokens, so this scans allShareLoginTokens() the same way RevokeShareLoginTokens
// does. Everything runs in one MULTI/EXEC, matching DeleteShareRecipient.
func (p DatabaseProvider) DeleteShareGrants(resourceType int, resourceId string) {
	if resourceId == "" {
		return
	}
	grants := p.GetShareGrants(resourceType, resourceId)
	tokens := p.allShareLoginTokens()

	conn := p.pool.Get()
	defer conn.Close()
	helper.Check(conn.Send("MULTI"))
	for _, grant := range grants {
		key := grantKey(resourceType, resourceId, grant.RecipientId)
		helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareGrant+key))
		helper.Check(conn.Send("HDEL", p.dbPrefix+prefixShareGrantByUser+strconv.Itoa(grant.RecipientId), key))
	}
	for _, token := range tokens {
		if token.ResourceType == resourceType && token.ResourceId == resourceId {
			helper.Check(conn.Send("DEL", p.dbPrefix+prefixShareLoginToken+token.TokenHash))
		}
	}
	_, err := conn.Do("EXEC")
	helper.Check(err)
}

// ---------------------------------------------------------------------------
// Login tokens and sessions
// ---------------------------------------------------------------------------

// AcquireShareGrantDownload atomically records one download by this recipient, under the window
// rule AcquireDownload applies to a file: the recipient's allowance is spent only when this call
// opens a window, and a request arriving inside an open window is granted for free. The grant's
// LastDownloadAt, which this already wrote before windows existed, is the window start.
//
// The existence check, the window check, the allowance test and the increment all run inside one
// Lua script, which Redis executes atomically. This follows acquireWindowedDownload in Redis.go,
// written for the same reason: it is what keeps the operation correct when several Gokapi
// instances share one Redis. It is a script of its own rather than a call into that helper
// because a grant's allowance is a used/allowed pair with 0 meaning unlimited, not a countdown to
// zero.
//
// A read-then-increment-then-roll-back version of this was wrong in a way that
// failed OPEN. If the grant were revoked between the read and the HINCRBY, the
// HINCRBY would recreate the hash with only a DownloadsUsed field; HasShareGrant
// tests key existence, and a hash with no DownloadsAllowed field scans as 0,
// which means unlimited. A revoked recipient would have regained unlimited
// access. The HEXISTS check below is inside the script precisely so that
// window cannot exist.
func (p DatabaseProvider) AcquireShareGrantDownload(resourceType int, resourceId string, recipientId int, timeNow, leeway int64) (bool, bool) {
	const script = `
if redis.call('HEXISTS', KEYS[1], 'RecipientId') == 0 then
	return 0
end
local lastDownloadAt = tonumber(redis.call('HGET', KEYS[1], 'LastDownloadAt')) or 0
if lastDownloadAt > tonumber(ARGV[2]) then
	return 1
end
local allowed = tonumber(redis.call('HGET', KEYS[1], 'DownloadsAllowed')) or 0
local used = tonumber(redis.call('HGET', KEYS[1], 'DownloadsUsed')) or 0
if allowed ~= 0 and used >= allowed then
	return 0
end
redis.call('HINCRBY', KEYS[1], 'DownloadsUsed', 1)
redis.call('HSET', KEYS[1], 'LastDownloadAt', ARGV[1])
return 2
`
	key := p.dbPrefix + prefixShareGrant + grantKey(resourceType, resourceId, recipientId)
	conn := p.pool.Get()
	defer conn.Close()
	result, err := conn.Do("EVAL", script, "1", key, timeNow, timeNow-leeway)
	resultInt, err2 := redigo.Int(result, err)
	helper.Check(err2)
	return resultInt > 0, resultInt == 2
}

// SaveShareLoginToken stores a magic link.
func (p DatabaseProvider) SaveShareLoginToken(token models.ShareLoginToken) {
	p.setHashMap(p.buildArgs(prefixShareLoginToken + token.TokenHash).AddFlat(token))
}

// GetShareLoginToken returns the token with this hash, or false.
func (p DatabaseProvider) GetShareLoginToken(tokenHash string) (models.ShareLoginToken, bool) {
	if tokenHash == "" {
		return models.ShareLoginToken{}, false
	}
	values, ok := p.getHashMap(prefixShareLoginToken + tokenHash)
	if !ok {
		return models.ShareLoginToken{}, false
	}
	var result models.ShareLoginToken
	helper.Check(redigo.ScanStruct(values, &result))
	return result, true
}

// MarkShareLoginTokenUsed records the first redemption, for audit only. The
// link stays usable afterwards: it is reusable by design.
//
// The zero test and the write are one Lua script, matching the SQL providers,
// which put the same guard in the UPDATE's WHERE clause. Read-then-write would
// let two concurrent first redemptions both pass, and the recorded "first use"
// would be whichever wrote last rather than the one that actually came first.
func (p DatabaseProvider) MarkShareLoginTokenUsed(tokenHash string, usedAt int64) {
	const script = `
if redis.call('HEXISTS', KEYS[1], 'TokenHash') == 0 then
	return 0
end
local first = tonumber(redis.call('HGET', KEYS[1], 'FirstUsedAt')) or 0
if first ~= 0 then
	return 0
end
redis.call('HSET', KEYS[1], 'FirstUsedAt', ARGV[1])
return 1
`
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("EVAL", script, "1", p.dbPrefix+prefixShareLoginToken+tokenHash, usedAt)
	helper.Check(err)
}

// GetLastShareLoginTokenTime returns when the most recent link for this
// recipient and resource was issued, or 0 if there is none.
func (p DatabaseProvider) GetLastShareLoginTokenTime(recipientId int, resourceType int, resourceId string) int64 {
	var latest int64
	for _, token := range p.allShareLoginTokens() {
		if token.RecipientId != recipientId || token.ResourceType != resourceType ||
			token.ResourceId != resourceId {
			continue
		}
		if token.CreatedAt > latest {
			latest = token.CreatedAt
		}
	}
	return latest
}

// RevokeShareLoginTokens retires every live link for this recipient and
// resource, so a link in an older mail stops working the moment a replacement
// is issued.
func (p DatabaseProvider) RevokeShareLoginTokens(recipientId int, resourceType int, resourceId string) {
	for _, token := range p.allShareLoginTokens() {
		if token.RecipientId != recipientId || token.ResourceType != resourceType ||
			token.ResourceId != resourceId || token.IsRevoked {
			continue
		}
		p.setHashmapField(prefixShareLoginToken+token.TokenHash, "IsRevoked", true)
	}
}

// CleanUpExpiredShareLoginTokens removes links that have expired.
func (p DatabaseProvider) CleanUpExpiredShareLoginTokens(now int64) {
	for _, token := range p.allShareLoginTokens() {
		if token.ExpiresAt < now {
			p.deleteKey(prefixShareLoginToken + token.TokenHash)
		}
	}
}

// GetAllShareLoginTokens returns every stored link.
func (p DatabaseProvider) GetAllShareLoginTokens() []models.ShareLoginToken {
	return p.allShareLoginTokens()
}

// allShareLoginTokens reads every stored link. Redis has no secondary index,
// so the recipient-and-resource queries above scan. Acceptable because these
// run on resend and cleanup, never on the download path, which looks a token
// up directly by its hash.
func (p DatabaseProvider) allShareLoginTokens() []models.ShareLoginToken {
	result := make([]models.ShareLoginToken, 0)
	for _, values := range p.getAllHashesWithPrefix(prefixShareLoginToken) {
		var token models.ShareLoginToken
		helper.Check(redigo.ScanStruct(values, &token))
		result = append(result, token)
	}
	return result
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
