package logging

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/environment/deprecation"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

var logPath = "config/log.txt"
var mutex sync.Mutex

const categoryInfo = "info"
const categoryDownload = "download"
const categoryUpload = "upload"
const categoryEdit = "edit"
const categoryAuth = "auth"
const categoryWarning = "warning"
const categoryDenied = "denied"
const categoryExpiry = "expiry"
const categoryApiKey = "apikey"
const categoryConfig = "config"

var outputToStdout = false
var useCloudflare = false

var parsedTrustedIPs []net.IP
var parsedTrustedCIDRs []*net.IPNet

// Init sets the path where to write the log file to
func Init(filePath string) {
	logPath = filePath + "/log.txt"
	env := environment.New()
	outputToStdout = env.LogToStdout
	useCloudflare = env.UseCloudFlare
	parseTrustedProxies(env.TrustedProxies, !env.DisableDockerTrustedProxy)
	initAudit(filePath)
}

// parseTrustedProxies processes the raw strings into net.IP and net.IPNet objects
func parseTrustedProxies(proxies []string, useDockerSubnet bool) {
	parsedTrustedIPs = nil
	parsedTrustedCIDRs = nil

	if environment.IsDockerInstance() && useDockerSubnet {
		subnet, err := getDockerSubnet()
		if err == nil {
			parsedTrustedCIDRs = append(parsedTrustedCIDRs, subnet)
		}
	}

	for _, proxy := range proxies {
		proxy = strings.TrimSpace(proxy)
		if strings.Contains(proxy, "/") {
			// Handle CIDR (e.g., "10.0.0.0/24")
			_, ipNet, err := net.ParseCIDR(proxy)
			if err == nil {
				parsedTrustedCIDRs = append(parsedTrustedCIDRs, ipNet)
			}
		} else {
			// Handle Fixed IP (e.g., "127.0.0.1")
			ip := net.ParseIP(proxy)
			if ip != nil {
				parsedTrustedIPs = append(parsedTrustedIPs, ip)
			}
		}
	}
}

func getDockerSubnet() (*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			// Docker typically uses these private ranges
			// Common: 172.16.0.0/12, 192.168.0.0/16, 10.0.0.0/8
			// Docker bridge default: 172.17.0.0/16
			if ipnet.IP.IsPrivate() && !ipnet.IP.IsLoopback() {
				// Skip if it's just the host IP (not a subnet)
				if ipnet.IP.To4() != nil {
					return ipnet, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no Docker subnet found")
}

// GetAll returns all log entries as a single string and if the log file exists
func GetAll() (string, bool) {
	exists, err := helper.FileExists(logPath)
	helper.Check(err)
	if exists {
		content, err := os.ReadFile(logPath)
		helper.Check(err)
		return string(content), true
	}
	return fmt.Sprintf("[%s] No log file found!", categoryWarning), false
}

// GetSince returns all log entries since a given timestamp
func GetSince(timestamp int64) string {
	exists, err := helper.FileExists(logPath)
	helper.Check(err)
	if !exists {
		return fmt.Sprintf("[%s] No log file found!", categoryWarning)
	}
	var (
		lines  []string
		output strings.Builder
	)

	err = readLinesReverse(logPath, timestamp, func(line string) (error, bool) {
		ts, err := parseTimeLogEntry(line)
		if err != nil {
			return nil, false // skip malformed lines
		}

		if ts.Unix() < timestamp {
			return nil, true
		}

		lines = append(lines, line)
		return nil, false
	})

	helper.Check(err)

	for i := len(lines) - 1; i >= 0; i-- {
		output.WriteString(lines[i])
		output.WriteByte('\n')
	}

	return output.String()
}

func readLinesReverse(path string, maxTime int64, handleLine func(string) (error, bool)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	const chunkSize = 4096
	var buffer []byte

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.ModTime().Unix() < maxTime {
		return nil
	}

	offset := info.Size()

	for offset > 0 {
		readSize := int64(chunkSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		_, err = file.Seek(offset, 0)
		if err != nil {
			return err
		}

		chunk := make([]byte, readSize)
		_, err = file.Read(chunk)
		if err != nil {
			return err
		}

		buffer = append(chunk, buffer...)
		for {
			idx := len(buffer) - 1
			for idx >= 0 && buffer[idx] != '\n' {
				idx--
			}
			if idx < 0 {
				break
			}
			line := string(buffer[idx+1:])
			buffer = buffer[:idx]
			err, endOfLine := handleLine(line)
			if err != nil || endOfLine {
				return err
			}
		}
	}

	// Handle the first line (start of file)
	if len(buffer) > 0 {
		err, endOfLine := handleLine(string(buffer))
		if err != nil || endOfLine {
			return err
		}
	}
	return nil
}

// createLogEntry adds a line to the logfile including the current date. Also outputs to Stdout if set.
func createLogEntry(category, text string, blocking bool) {
	output := createLogFormat(category, text)
	if outputToStdout {
		fmt.Println(output)
	}
	if blocking {
		writeToFile(output)
	} else {
		go writeToFile(output)
	}
}

func createLogFormat(category, text string) string {
	return createLogFormatCustomTimestamp(category, text, time.Now())
}
func createLogFormatCustomTimestamp(category, text string, timestamp time.Time) string {
	return fmt.Sprintf("%s   [%s] %s", getDate(timestamp), category, text)
}

// LogStartup adds a log entry to indicate that Gokapi has started. Non-blocking
func LogStartup() {
	createLogEntry(categoryInfo, "Gokapi started", false)
}

// LogShutdown adds a log entry to indicate that Gokapi is shutting down. Blocking call
func LogShutdown() {
	createLogEntry(categoryInfo, "Gokapi shutting down", true)
}

// LogSetup adds a log entry to indicate that the setup was run. Non-blocking
func LogSetup() {
	createLogEntry(categoryAuth, "Re-running Gokapi setup", false)
}

// LogDeploymentPassword adds a log entry to indicate that a deployment password was set. Non-blocking
func LogDeploymentPassword() {
	createLogEntry(categoryAuth, "Setting new admin password", false)
}

// LogUserDeletion adds a log entry to indicate that a user was deleted. Non-blocking
func LogUserDeletion(modifiedUser, userEditor models.User) {
	createLogEntry(categoryAuth, fmt.Sprintf("%s (#%d) was deleted by %s (user #%d)",
		modifiedUser.Name, modifiedUser.Id, userEditor.Name, userEditor.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "user.deleted",
		Outcome:  OutcomeSuccess,
		Actor:    AuditActor{UserId: userEditor.Id, Email: userEditor.Name},
		Detail:   fmt.Sprintf("target user %s (#%d)", modifiedUser.Name, modifiedUser.Id),
	})
}

// LogUserEdit adds a log entry to indicate that a user was modified. Non-blocking
func LogUserEdit(modifiedUser, userEditor models.User) {
	createLogEntry(categoryAuth, fmt.Sprintf("%s (#%d) was modified by %s (user #%d)",
		modifiedUser.Name, modifiedUser.Id, userEditor.Name, userEditor.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "user.edited",
		Outcome:  OutcomeSuccess,
		Actor:    AuditActor{UserId: userEditor.Id, Email: userEditor.Name},
		Detail:   fmt.Sprintf("target user %s (#%d)", modifiedUser.Name, modifiedUser.Id),
	})
}

// LogUserCreation adds a log entry to indicate that a user was created. Non-blocking
func LogUserCreation(modifiedUser, userEditor models.User) {
	createLogEntry(categoryAuth, fmt.Sprintf("%s (#%d) was created by %s (user #%d)",
		modifiedUser.Name, modifiedUser.Id, userEditor.Name, userEditor.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "user.created",
		Outcome:  OutcomeSuccess,
		Actor:    AuditActor{UserId: userEditor.Id, Email: userEditor.Name},
		Detail:   fmt.Sprintf("target user %s (#%d)", modifiedUser.Name, modifiedUser.Id),
	})
}

// LogInvalidLogin adds a log entry to indicate that an invalid login was attempted. Non-blocking
func LogInvalidLogin(username, ip string) {
	createLogEntry(categoryAuth, fmt.Sprintf("Invalid login for user %s by IP %s", username, ip), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "login",
		Outcome:  OutcomeFailure,
		Ip:       ip,
		Actor:    AuditActor{Email: username},
		Error:    "invalid credentials",
	})
}

// LogOauthTakeoverRejected adds a log entry to indicate that an OAuth login was rejected because
// the target account was not provisioned for OAuth (or its OIDC subject no longer matches),
// i.e. a rejected account-takeover attempt rather than an ordinary wrong password. Kept distinct
// from LogInvalidLogin so this signal is not lost in routine failed-login noise. Non-blocking
func LogOauthTakeoverRejected(username, ip string) {
	createLogEntry(categoryAuth, fmt.Sprintf("Rejected OAuth login for %s by IP %s: account not provisioned for this provider", username, ip), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "login.takeover_rejected",
		Outcome:  OutcomeDenied,
		Ip:       ip,
		Actor:    AuditActor{Email: username},
		Error:    "oauth login rejected: account not provisioned for this authentication provider",
	})
}

// LogValidLogin adds a log entry to indicate that a login was successful. Non-blocking
// oidcSubject is the OIDC "sub" claim for OAuth2 logins, empty otherwise: this is the only
// point in the request lifecycle where Gokapi still has it, so it is recorded here or not at
// all - sessions created after login do not carry it, and later actions by the same user
// cannot be tied back to it.
func LogValidLogin(username, oidcSubject, ip string) {
	createLogEntry(categoryAuth, fmt.Sprintf("%s logged in sucessfully", username), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "login",
		Outcome:  OutcomeSuccess,
		Ip:       ip,
		Actor:    AuditActor{Email: username, OidcSubject: oidcSubject},
	})
}

// LogLogout adds a log entry to indicate that a user logged out. Non-blocking
func LogLogout(user models.User, r *http.Request) {
	createLogEntry(categoryAuth, fmt.Sprintf("%s (user #%d) logged out", user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryAuth,
		Action:   "logout",
		Outcome:  OutcomeSuccess,
		Ip:       GetIpAddress(r),
		Actor:    AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// downloadFileConfig captures a file's sharing configuration for the audit chain
func downloadFileConfig(file models.File) *AuditFileConfig {
	return &AuditFileConfig{
		// DownloadCount + DownloadsRemaining is the file's original total download allowance,
		// and is invariant over the file's lifetime (each decrement of one is paired with an
		// increment of the other) - unlike DownloadsRemaining alone, which would misreport a
		// link with more than one allowed download as "one-time" once only one download is left.
		OneTime:           !file.UnlimitedDownloads && file.DownloadCount+file.DownloadsRemaining == 1,
		ExpiresAt:         file.ExpireAt,
		PasswordProtected: file.PasswordHash != "",
	}
}

// LogDownload records that a file was served to a client. This is a guarded, fail-closed
// event: the audit entry is fsync'd to the local chain before this function returns, and the
// caller must not write any file bytes to the response if it returns a non-nil error - refuse
// the request instead. The identity of the requester is read from r if it was attached with
// WithActor (admin/API downloads); public share/hotlink downloads carry no identity by design
// and are recorded as anonymous.
func LogDownload(file models.File, r *http.Request, saveIp bool) error {
	ip := ""
	if saveIp {
		ip = GetIpAddress(r)
		createLogEntry(categoryDownload, fmt.Sprintf("%s, IP %s, ID %s, Useragent %s", file.Name, ip, file.Id, sanitiseUserAgent(r)), false)
	} else {
		createLogEntry(categoryDownload, fmt.Sprintf("%s, ID %s, Useragent %s", file.Name, file.Id, sanitiseUserAgent(r)), false)
	}
	return appendAuditEntry(AuditEntry{
		Category:   categoryDownload,
		Action:     "download",
		Outcome:    OutcomeSuccess,
		Ip:         ip,
		FileId:     file.Id,
		Actor:      buildActorFromRequest(r),
		FileConfig: downloadFileConfig(file),
	})
}

// LogAuditWriteFailure is a best-effort fallback for the one case where the primary structured
// audit chain write fails AFTER an irreversible state change already happened - specifically,
// ServeFile's download-allowance decrement, which lives in the W2 item and is not reordered
// around the audit write here (see the call site). It writes into the human-readable log.txt
// only, a different file than the one that just failed, so it has an independent chance of
// succeeding; it is blocking, since by the time this is called the request is already being
// refused, and it is not part of the chain and carries none of its tamper-evidence guarantees.
func LogAuditWriteFailure(context string, auditErr error) {
	createLogEntry(categoryWarning, fmt.Sprintf("AUDIT WRITE FAILED after an irreversible state change (%s): %s", context, auditErr), true)
}

// LogDownloadDenied records that a download attempt was refused, e.g. a wrong file password or
// an exhausted/expired link. This is a guarded, fail-closed event like LogDownload: nothing
// about the file may be revealed to the caller (not even that it is expired vs. wrong
// password, which the calling handler controls) if this returns a non-nil error - refuse with
// a generic error instead of rendering the normal denial page.
func LogDownloadDenied(file models.File, r *http.Request, saveIp bool, reason string) error {
	ip := ""
	if saveIp {
		ip = GetIpAddress(r)
	}
	createLogEntry(categoryDenied, fmt.Sprintf("%s, ID %s, IP %s, download denied: %s", file.Name, file.Id, ip, reason), false)
	return appendAuditEntry(AuditEntry{
		Category:   categoryDenied,
		Action:     "download",
		Outcome:    OutcomeDenied,
		Ip:         ip,
		FileId:     file.Id,
		Actor:      buildActorFromRequest(r),
		FileConfig: downloadFileConfig(file),
		Error:      reason,
	})
}

var regexUserAgent = regexp.MustCompile(`[^A-Za-z0-9/. ;:+(|)_\-,]`)

func sanitiseUserAgent(r *http.Request) string {
	return regexUserAgent.ReplaceAllString(r.UserAgent(), "")
}

// LogUpload records that a file was created. This is a guarded, fail-closed event: the audit
// entry is fsync'd to the local chain before this function returns, and the caller must not
// confirm success to the client if it returns a non-nil error - the uploaded file should be
// removed again and the request refused instead.
func LogUpload(file models.File, user models.User, fr models.FileRequest, r *http.Request, saveIp bool) error {
	ip := ""
	if saveIp {
		ip = GetIpAddress(r)
	}
	action := "upload"
	if fr.Id != "" {
		createLogEntry(categoryUpload, fmt.Sprintf("%s, ID %s, IP %s, uploaded to file request %s (%s), owned by %s (user #%d) ", file.Name, ip, file.Id, fr.Id, fr.Name, user.Name, user.Id), false)
		action = "upload.filerequest"
	} else {
		createLogEntry(categoryUpload, fmt.Sprintf("%s, ID %s, IP %s, uploaded by %s (user #%d)", file.Name, ip, file.Id, user.Name, user.Id), false)
	}
	return appendAuditEntry(AuditEntry{
		Category:   categoryUpload,
		Action:     action,
		Outcome:    OutcomeSuccess,
		Ip:         ip,
		FileId:     file.Id,
		RequestId:  fr.Id,
		Actor:      AuditActor{UserId: user.Id, Email: user.Name},
		FileConfig: downloadFileConfig(file),
	})
}

// LogEdit adds a log entry when an upload was edited. Non-Blocking
func LogEdit(file models.File, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("%s, ID %s, edited by %s (user #%d)", file.Name, file.Id, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category:   categoryEdit,
		Action:     "file.edited",
		Outcome:    OutcomeSuccess,
		FileId:     file.Id,
		Actor:      AuditActor{UserId: user.Id, Email: user.Name},
		FileConfig: downloadFileConfig(file),
	})
}

// LogCreateFileRequest adds a log entry when a file request was added. Non-Blocking
func LogCreateFileRequest(fr models.FileRequest, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("File request %s (%s) created by %s (user #%d)", fr.Id, fr.Name, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category:  categoryEdit,
		Action:    "filerequest.created",
		Outcome:   OutcomeSuccess,
		RequestId: fr.Id,
		Actor:     AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogEditFileRequest adds a log entry when a file request was edited. Non-Blocking
func LogEditFileRequest(fr models.FileRequest, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("File request %s (%s) created by %s (user #%d)", fr.Id, fr.Name, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category:  categoryEdit,
		Action:    "filerequest.edited",
		Outcome:   OutcomeSuccess,
		RequestId: fr.Id,
		Actor:     AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogDeleteFileRequest adds a log entry when a file request was deleted. Non-Blocking
func LogDeleteFileRequest(fr models.FileRequest, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("File request %s (%s) and associated files deleted by %s (user #%d)", fr.Id, fr.Name, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category:  categoryEdit,
		Action:    "filerequest.deleted",
		Outcome:   OutcomeSuccess,
		RequestId: fr.Id,
		Actor:     AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogReplace adds a log entry when an upload was replaced. Non-Blocking
func LogReplace(originalFile, newContent models.File, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("%s, ID %s had content replaced with %s (ID %s) by %s (user #%d)",
		originalFile.Name, originalFile.Id, newContent.Name, newContent.Id, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryEdit,
		Action:   "file.replaced",
		Outcome:  OutcomeSuccess,
		FileId:   originalFile.Id,
		Actor:    AuditActor{UserId: user.Id, Email: user.Name},
		Detail:   fmt.Sprintf("content replaced with new file ID %s", newContent.Id),
	})
}

// LogDelete adds a log entry when an upload was deleted. Fail-closed like LogDownload: the
// audit record is fsync'd to durable local storage before this returns, and the caller must not
// proceed with the deletion (the files must still exist) if this returns a non-nil error -
// refuse the request instead. This mirrors the pattern in FileServing.go rather than the
// fire-and-forget appendAuditEntryAsync used for most other edit/log events, since a deletion is
// irreversible: an entry lost to a local write failure here can never be reconstructed.
func LogDelete(file models.File, user models.User) error {
	createLogEntry(categoryEdit, fmt.Sprintf("%s, ID %s, deleted by %s (user #%d)", file.Name, file.Id, user.Name, user.Id), false)
	return appendAuditEntry(AuditEntry{
		Category: categoryEdit,
		Action:   "file.deleted",
		Outcome:  OutcomeSuccess,
		FileId:   file.Id,
		Actor:    AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogFolderCreate adds a log entry when a folder was created. Non-Blocking
func LogFolderCreate(bundle models.FileBundle, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("Folder %s (%s) created by %s (user #%d)", bundle.Id, bundle.Name, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryEdit,
		Action:   "folder.created",
		Outcome:  OutcomeSuccess,
		BundleId: bundle.Id,
		Actor:    AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogFolderDelete adds a log entry when a folder was deleted. Fail-closed, see LogDelete.
func LogFolderDelete(bundle models.FileBundle, user models.User) error {
	createLogEntry(categoryEdit, fmt.Sprintf("Folder %s (%s) and associated files deleted by %s (user #%d)", bundle.Id, bundle.Name, user.Name, user.Id), false)
	return appendAuditEntry(AuditEntry{
		Category: categoryEdit,
		Action:   "folder.deleted",
		Outcome:  OutcomeSuccess,
		BundleId: bundle.Id,
		Actor:    AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogRestore adds a log entry when the pending deletion of a file was cancelled and the file restored. Non-Blocking
func LogRestore(file models.File, user models.User) {
	createLogEntry(categoryEdit, fmt.Sprintf("%s, ID %s, restored by %s (user #%d)", file.Name, file.Id, user.Name, user.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryEdit,
		Action:   "file.restored",
		Outcome:  OutcomeSuccess,
		FileId:   file.Id,
		Actor:    AuditActor{UserId: user.Id, Email: user.Name},
	})
}

// LogFileExpired records that a file's metadata (and, unless deduplicated, its stored blob)
// was automatically disposed of by the periodic cleanup job. There is no requester to
// attribute this to; it is a system action. Non-blocking, as this runs off the request path.
func LogFileExpired(file models.File, reason string) {
	createLogEntry(categoryExpiry, fmt.Sprintf("%s, ID %s, automatically disposed of: %s", file.Name, file.Id, reason), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryExpiry,
		Action:   "file.disposed",
		Outcome:  OutcomeSuccess,
		FileId:   file.Id,
		Detail:   reason,
	})
}

// LogApiKeyCreated records that an API key was created. Non-blocking.
func LogApiKeyCreated(key models.ApiKey, actor models.User) {
	createLogEntry(categoryApiKey, fmt.Sprintf("API key %s (%s) created by %s (user #%d)", key.GetRedactedId(), key.FriendlyName, actor.Name, actor.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryApiKey,
		Action:   "apikey.created",
		Outcome:  OutcomeSuccess,
		Actor:    AuditActor{UserId: actor.Id, Email: actor.Name},
		Detail:   fmt.Sprintf("key %s (%s), owner user #%d", key.GetRedactedId(), key.FriendlyName, key.UserId),
	})
}

// LogApiKeyDeleted records that an API key was deleted. Non-blocking.
func LogApiKeyDeleted(key models.ApiKey, actor models.User) {
	createLogEntry(categoryApiKey, fmt.Sprintf("API key %s (%s) deleted by %s (user #%d)", key.GetRedactedId(), key.FriendlyName, actor.Name, actor.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryApiKey,
		Action:   "apikey.deleted",
		Outcome:  OutcomeSuccess,
		Actor:    AuditActor{UserId: actor.Id, Email: actor.Name},
		Detail:   fmt.Sprintf("key %s (%s), owner user #%d", key.GetRedactedId(), key.FriendlyName, key.UserId),
	})
}

// LogApiKeyPermissionChanged records that an API key's permissions were changed. Non-blocking.
func LogApiKeyPermissionChanged(key models.ApiKey, actor models.User, permission string, granted bool) {
	verb := "granted"
	if !granted {
		verb = "revoked"
	}
	createLogEntry(categoryApiKey, fmt.Sprintf("Permission %s %s for API key %s (%s) by %s (user #%d)", permission, verb, key.GetRedactedId(), key.FriendlyName, actor.Name, actor.Id), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryApiKey,
		Action:   "apikey.permission_changed",
		Outcome:  OutcomeSuccess,
		Actor:    AuditActor{UserId: actor.Id, Email: actor.Name},
		Detail:   fmt.Sprintf("key %s (%s): permission %s %s", key.GetRedactedId(), key.FriendlyName, permission, verb),
	})
}

// LogEncryptionConfigChange records that the encryption configuration was changed via the
// reconfiguration setup. Non-blocking. There is no models.User to attribute this to: the
// reconfiguration setup is protected by its own single-use, generated credentials rather than
// a normal account (see configuration/setup.RunConfigModification).
func LogEncryptionConfigChange(oldLevel, newLevel int, r *http.Request) {
	createLogEntry(categoryConfig, fmt.Sprintf("Encryption level changed from %d to %d via reconfiguration setup", oldLevel, newLevel), false)
	appendAuditEntryAsync(AuditEntry{
		Category: categoryConfig,
		Action:   "config.encryption_changed",
		Outcome:  OutcomeSuccess,
		Ip:       GetIpAddress(r),
		Detail:   fmt.Sprintf("encryption level %d -> %d, via reconfiguration setup", oldLevel, newLevel),
	})
}

// LogDeprecation adds a log entry to indicate that a deprecated feature is being used. Blocking
func LogDeprecation(dep deprecation.Deprecation) {
	createLogEntry(categoryWarning, "Deprecated feature: "+dep.Name, true)
	createLogEntry(categoryWarning, dep.Description, true)
	createLogEntry(categoryWarning, "See "+dep.DocUrl+" for more information.", true)
}

// DeleteLogs removes all logs before the cutoff timestamp and inserts a new log that the user
// deleted the previous logs
func DeleteLogs(userName string, userId int, cutoff int64, r *http.Request) {
	if cutoff == 0 {
		deleteAllLogs(userName, userId, r)
		return
	}
	mutex.Lock()
	logFile, err := os.ReadFile(logPath)
	helper.Check(err)
	var newFile strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(string(logFile)))
	newFile.WriteString(getLogDeletionMessage(userName, userId, r, time.Unix(cutoff, 0)))
	for scanner.Scan() {
		line := scanner.Text()
		timeEntry, err := parseTimeLogEntry(line)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if timeEntry.Unix() > cutoff {
			newFile.WriteString(line + "\n")
		}
	}
	err = os.WriteFile(logPath, []byte(newFile.String()), 0600)
	helper.Check(err)
	defer mutex.Unlock()
}

func parseTimeLogEntry(input string) (time.Time, error) {
	const layout = "Mon, 02 Jan 2006 15:04:05 MST"
	lineContent := strings.Split(input, "   [")
	return time.Parse(layout, lineContent[0])
}

func getLogDeletionMessage(userName string, userId int, r *http.Request, timestamp time.Time) string {
	return createLogFormatCustomTimestamp(categoryWarning, fmt.Sprintf("Previous logs deleted by %s (user #%d) on %s. IP: %s\n",
		userName, userId, getDate(time.Now()), GetIpAddress(r)), timestamp)
}

func deleteAllLogs(userName string, userId int, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()
	message := getLogDeletionMessage(userName, userId, r, time.Now())
	err := os.WriteFile(logPath, []byte(message), 0600)
	helper.Check(err)
}

func writeToFile(text string) {
	mutex.Lock()
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	helper.Check(err)
	defer file.Close()
	defer mutex.Unlock()
	_, err = file.WriteString(text + "\n")
	helper.Check(err)
}

func getDate(timestamp time.Time) string {
	return timestamp.UTC().Format(time.RFC1123)
}

func isTrustedProxy(ip net.IP) bool {
	// Check against fixed IPs
	for _, trustedIP := range parsedTrustedIPs {
		if trustedIP.Equal(ip) {
			return true
		}
	}

	// Check against CIDR ranges
	for _, trustedNet := range parsedTrustedCIDRs {
		if trustedNet.Contains(ip) {
			return true
		}
	}

	return false
}

// GetIpAddress returns the IP address of the requester
func GetIpAddress(r *http.Request) string {

	if useCloudflare {
		cfIp := r.Header.Get("CF-Connecting-IP")
		if cfIp != "" {
			return cfIp
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// Clean up if it is an IPv6 zone
	netIP := net.ParseIP(ip)

	// Check if the immediate connector is a Trusted Proxy and if yes, use their header for IP
	// Otherwise this returns the actual IP used for the connection
	if netIP != nil && isTrustedProxy(netIP) {

		// Check X-Forwarded-For
		// Ideally, use the last IP in the list if a proxy appends to it
		xff := r.Header.Get("X-FORWARDED-FOR")
		if xff != "" {
			ips := strings.Split(xff, ",")
			// Iterate from right to left, skip trusted proxies
			for i := len(ips) - 1; i >= 0; i-- {
				ipXff := strings.TrimSpace(ips[i])
				parsedIP := net.ParseIP(ipXff)
				if parsedIP != nil && !isTrustedProxy(parsedIP) {
					return ipXff
				}
			}
		}

		// Fallback to X-Real-Ip if XFF fails
		xri := r.Header.Get("X-REAL-IP")
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	return ip
}
