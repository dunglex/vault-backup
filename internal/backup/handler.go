package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
)

type Dependencies struct {
	RequireAdmin     func(http.ResponseWriter, *http.Request) bool
	RequestHTTPS     func(*http.Request) bool
	Enabled          func() bool
	Audit            func(*http.Request, string, string, string)
	Metadata         func(time.Time) (Metadata, error)
	CloseDatabases   func() error
	ReopenDatabases  func() error
	BeginMaintenance func(*http.Request)
	EndMaintenance   func()
	FailMaintenance  func()
	SaveSuccess      func(time.Time) error
}

type Handler struct {
	db     *sql.DB
	config Config
	deps   Dependencies

	dbMu      sync.RWMutex
	mu        sync.Mutex
	runMu     sync.Mutex
	scheduler gocron.Scheduler
	job       gocron.Job
}

func NewHandler(db *sql.DB, config Config, deps Dependencies) *Handler {
	return &Handler{db: db, config: config, deps: deps}
}

func (h *Handler) SetDB(db *sql.DB) {
	h.dbMu.Lock()
	h.db = db
	h.dbMu.Unlock()
}

func (h *Handler) database() *sql.DB {
	h.dbMu.RLock()
	defer h.dbMu.RUnlock()
	return h.db
}

func (h *Handler) Enabled() bool {
	if h.deps.Enabled != nil {
		return h.deps.Enabled()
	}
	enabled, err := ReadExtensionEnabled(h.database())
	return err == nil && enabled
}

func (h *Handler) unavailable(w http.ResponseWriter) bool {
	if h.Enabled() {
		return false
	}
	http.Error(w, "backup management is not enabled", http.StatusNotFound)
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	return h.deps.RequireAdmin != nil && h.deps.RequireAdmin(w, r)
}

func (h *Handler) requestIsHTTPS(r *http.Request) bool {
	if h.deps.RequestHTTPS != nil {
		return h.deps.RequestHTTPS(r)
	}
	return r.TLS != nil
}

func (h *Handler) audit(r *http.Request, outcome, detail string) {
	if h.deps.Audit != nil {
		h.deps.Audit(r, "server_backup", outcome, detail)
	}
}

func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if h.unavailable(w) {
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}
	enabled, cronExpression, lastSuccess, err := ReadSettings(h.database())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read backup settings"})
		return
	}
	s3Config, err := ReadS3Config(h.database())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read S3 backup settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"automatic_server_backup":     enabled,
		"server_backup_cron":          cronExpression,
		"server_backup_last_success":  lastSuccess,
		"s3_enabled":                  s3Config.Enabled,
		"s3_endpoint":                 s3Config.Endpoint,
		"s3_region":                   s3Config.Region,
		"s3_bucket":                   s3Config.Bucket,
		"s3_prefix":                   s3Config.Prefix,
		"s3_access_key_id":            s3Config.AccessKeyID,
		"s3_session_token_configured": s3Config.SessionToken != "",
		"s3_path_style":               s3Config.ForcePathStyle,
		"s3_secret_configured":        s3Config.SecretAccessKey != "",
	})
}

type settingsRequest struct {
	AutomaticServerBackup *bool   `json:"automatic_server_backup"`
	ServerBackupCron      *string `json:"server_backup_cron"`
	S3Enabled             *bool   `json:"s3_enabled"`
	S3Endpoint            *string `json:"s3_endpoint"`
	S3Region              *string `json:"s3_region"`
	S3Bucket              *string `json:"s3_bucket"`
	S3Prefix              *string `json:"s3_prefix"`
	S3AccessKeyID         *string `json:"s3_access_key_id"`
	S3SecretAccessKey     *string `json:"s3_secret_access_key"`
	S3SessionToken        *string `json:"s3_session_token"`
	S3PathStyle           *bool   `json:"s3_path_style"`
}

func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h.unavailable(w) {
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}
	if !h.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to change backup settings"})
		return
	}
	var request settingsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid backup settings"})
		return
	}
	enabled, cronExpression, _, err := ReadSettings(h.database())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read backup settings"})
		return
	}
	if request.AutomaticServerBackup != nil {
		enabled = *request.AutomaticServerBackup
	}
	if request.ServerBackupCron != nil {
		cronExpression = strings.TrimSpace(*request.ServerBackupCron)
	}
	if len(cronExpression) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "server backup cron expression is too long"})
		return
	}
	if err := ValidateCron(cronExpression); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if enabled {
		if err := ValidateDatabaseScope(h.config); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	s3Config, err := ReadS3Config(h.database())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read S3 backup settings"})
		return
	}
	if request.S3Enabled != nil {
		s3Config.Enabled = *request.S3Enabled
	}
	if request.S3Endpoint != nil {
		s3Config.Endpoint = strings.TrimSpace(*request.S3Endpoint)
	}
	if request.S3Region != nil {
		s3Config.Region = strings.TrimSpace(*request.S3Region)
	}
	if request.S3Bucket != nil {
		s3Config.Bucket = strings.TrimSpace(*request.S3Bucket)
	}
	if request.S3Prefix != nil {
		s3Config.Prefix = strings.Trim(strings.TrimSpace(*request.S3Prefix), "/")
	}
	if request.S3AccessKeyID != nil {
		s3Config.AccessKeyID = strings.TrimSpace(*request.S3AccessKeyID)
	}
	if request.S3SecretAccessKey != nil && strings.TrimSpace(*request.S3SecretAccessKey) != "" {
		s3Config.SecretAccessKey = *request.S3SecretAccessKey
	}
	if request.S3SessionToken != nil {
		s3Config.SessionToken = strings.TrimSpace(*request.S3SessionToken)
	}
	if request.S3PathStyle != nil {
		s3Config.ForcePathStyle = *request.S3PathStyle
	}
	if s3Config.Enabled {
		if err := ValidateS3Config(s3Config); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if request.Empty() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no backup settings provided"})
		return
	}
	if err := h.saveSettings(enabled, cronExpression, s3Config, request); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save backup settings"})
		return
	}
	if err := h.ConfigureSchedule(enabled, cronExpression); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settings were saved but the backup schedule could not be applied"})
		return
	}
	h.audit(r, "success", AutomaticSetting+"="+strconv.FormatBool(enabled)+","+CronSetting+"="+cronExpression)
	_, _, lastSuccess, _ := ReadSettings(h.database())
	writeJSON(w, http.StatusOK, map[string]any{
		"automatic_server_backup":     enabled,
		"server_backup_cron":          cronExpression,
		"server_backup_last_success":  lastSuccess,
		"s3_enabled":                  s3Config.Enabled,
		"s3_endpoint":                 s3Config.Endpoint,
		"s3_region":                   s3Config.Region,
		"s3_bucket":                   s3Config.Bucket,
		"s3_prefix":                   s3Config.Prefix,
		"s3_access_key_id":            s3Config.AccessKeyID,
		"s3_session_token_configured": s3Config.SessionToken != "",
		"s3_path_style":               s3Config.ForcePathStyle,
		"s3_secret_configured":        s3Config.SecretAccessKey != "",
	})
}

func (r settingsRequest) Empty() bool {
	return r.AutomaticServerBackup == nil && r.ServerBackupCron == nil &&
		r.S3Enabled == nil && r.S3Endpoint == nil && r.S3Region == nil &&
		r.S3Bucket == nil && r.S3Prefix == nil && r.S3AccessKeyID == nil &&
		r.S3SecretAccessKey == nil && r.S3SessionToken == nil && r.S3PathStyle == nil
}

func (h *Handler) saveSettings(enabled bool, cronExpression string, s3Config S3Config, request settingsRequest) error {
	tx, err := h.database().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		AutomaticSetting, strconv.FormatBool(enabled),
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		CronSetting, cronExpression,
	); err != nil {
		return err
	}
	s3Requested := !request.Empty() &&
		(request.S3Enabled != nil || request.S3Endpoint != nil || request.S3Region != nil ||
			request.S3Bucket != nil || request.S3Prefix != nil || request.S3AccessKeyID != nil ||
			request.S3SecretAccessKey != nil || request.S3SessionToken != nil || request.S3PathStyle != nil)
	if s3Requested {
		values := map[string]string{
			S3EnabledSetting:      strconv.FormatBool(s3Config.Enabled),
			S3EndpointSetting:     s3Config.Endpoint,
			S3RegionSetting:       s3Config.Region,
			S3BucketSetting:       s3Config.Bucket,
			S3PrefixSetting:       s3Config.Prefix,
			S3AccessKeySetting:    s3Config.AccessKeyID,
			S3SecretKeySetting:    s3Config.SecretAccessKey,
			S3SessionTokenSetting: s3Config.SessionToken,
			S3PathStyleSetting:    strconv.FormatBool(s3Config.ForcePathStyle),
		}
		for key, value := range values {
			if _, err := tx.Exec(
				"INSERT INTO server_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
				key, value,
			); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if h.unavailable(w) {
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}
	backups, err := List(h.config.BackupDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read server backups"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": backups})
}

func (h *Handler) TestS3(w http.ResponseWriter, r *http.Request) {
	if h.unavailable(w) {
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}
	if !h.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to test S3 connection"})
		return
	}
	var request struct {
		S3Endpoint        *string `json:"s3_endpoint"`
		S3Region          *string `json:"s3_region"`
		S3Bucket          *string `json:"s3_bucket"`
		S3Prefix          *string `json:"s3_prefix"`
		S3AccessKeyID     *string `json:"s3_access_key_id"`
		S3SecretAccessKey *string `json:"s3_secret_access_key"`
		S3SessionToken    *string `json:"s3_session_token"`
		S3PathStyle       *bool   `json:"s3_path_style"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid S3 test request"})
		return
	}
	config, err := ReadS3Config(h.database())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read S3 backup settings"})
		return
	}
	if request.S3Endpoint != nil {
		config.Endpoint = strings.TrimSpace(*request.S3Endpoint)
	}
	if request.S3Region != nil {
		config.Region = strings.TrimSpace(*request.S3Region)
	}
	if request.S3Bucket != nil {
		config.Bucket = strings.TrimSpace(*request.S3Bucket)
	}
	if request.S3Prefix != nil {
		config.Prefix = strings.Trim(strings.TrimSpace(*request.S3Prefix), "/")
	}
	if request.S3AccessKeyID != nil {
		config.AccessKeyID = strings.TrimSpace(*request.S3AccessKeyID)
	}
	if request.S3SecretAccessKey != nil && strings.TrimSpace(*request.S3SecretAccessKey) != "" {
		config.SecretAccessKey = *request.S3SecretAccessKey
	}
	if request.S3SessionToken != nil {
		config.SessionToken = strings.TrimSpace(*request.S3SessionToken)
	}
	if request.S3PathStyle != nil {
		config.ForcePathStyle = *request.S3PathStyle
	}
	config.Enabled = true
	if err := TestS3Connection(config); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"connected": true})
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	if h.unavailable(w) {
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}
	if !h.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to create server backups"})
		return
	}
	if !h.runMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a server backup or restore is already in progress"})
		return
	}
	defer h.runMu.Unlock()
	h.audit(r, "started", "")
	if h.deps.BeginMaintenance != nil {
		h.deps.BeginMaintenance(r)
		defer h.deps.EndMaintenance()
	}
	createdAt := time.Now().UTC()
	metadata, err := h.deps.Metadata(createdAt)
	if err != nil {
		h.audit(r, "failure", "metadata_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not collect server backup metadata"})
		return
	}
	if h.deps.CloseDatabases != nil {
		if err := h.deps.CloseDatabases(); err != nil {
			if h.deps.ReopenDatabases != nil {
				_ = h.deps.ReopenDatabases()
			}
			h.audit(r, "failure", "database_close_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not pause databases for server backup"})
			return
		}
	}
	archivePath, backupErr := CreateWithMetadata(h.config.DataDir, h.config.BackupDir, metadata)
	if h.deps.ReopenDatabases != nil {
		if err := h.deps.ReopenDatabases(); err != nil {
			h.audit(r, "failure", "database_reopen_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server backup created but databases could not be reopened"})
			return
		}
	}
	if backupErr != nil {
		h.audit(r, "failure", "backup_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create server backup"})
		return
	}
	s3Key, s3Err := h.copyToS3(archivePath)
	if s3Err != nil {
		h.audit(r, "failure", "s3_copy_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "backup created locally but could not be copied to S3"})
		return
	}
	if h.deps.SaveSuccess != nil {
		_ = h.deps.SaveSuccess(time.Now().UTC())
	}
	_ = Prune(h.config.BackupDir, time.Now().UTC().Add(-Retention))
	detail := ""
	if s3Key != "" {
		detail = "s3_key=" + s3Key
	}
	h.audit(r, "success", detail)
	writeJSON(w, http.StatusCreated, map[string]string{"name": filepath.Base(archivePath), "s3_key": s3Key})
}

func (h *Handler) copyToS3(archivePath string) (string, error) {
	config, err := ReadS3Config(h.database())
	if err != nil {
		return "", err
	}
	if !config.Enabled {
		return "", nil
	}
	return CopyToS3(config, archivePath)
}

func (h *Handler) Restore(w http.ResponseWriter, r *http.Request) {
	if h.unavailable(w) {
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}
	if !h.requestIsHTTPS(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "HTTPS is required to restore server backups"})
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid restore request"})
		return
	}
	if !h.runMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a server backup or restore is already in progress"})
		return
	}
	defer h.runMu.Unlock()
	if h.deps.BeginMaintenance != nil {
		h.deps.BeginMaintenance(r)
		defer h.deps.EndMaintenance()
	}
	if h.deps.CloseDatabases != nil {
		if err := h.deps.CloseDatabases(); err != nil {
			if h.deps.ReopenDatabases != nil {
				_ = h.deps.ReopenDatabases()
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not pause databases for server restore"})
			return
		}
	}
	restoreErr := Restore(h.config.BackupDir, h.config.DataDir, request.Name, h.config.MasterKey)
	if h.deps.ReopenDatabases != nil {
		reopenErr := h.deps.ReopenDatabases()
		if reopenErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server data restored but databases could not be reopened"})
			return
		}
	}
	if restoreErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": restoreErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": request.Name})
}

func (h *Handler) StartScheduler() error {
	scheduler, err := gocron.NewScheduler(
		gocron.WithLocation(time.UTC),
		gocron.WithLimitConcurrentJobs(1, gocron.LimitModeReschedule),
	)
	if err != nil {
		return fmt.Errorf("create server backup scheduler: %w", err)
	}
	h.scheduler = scheduler
	enabled, expression, _, err := ReadSettings(h.database())
	if err != nil {
		_ = scheduler.Shutdown()
		return err
	}
	if h.Enabled() && enabled {
		if err := ValidateDatabaseScope(h.config); err != nil {
			_ = scheduler.Shutdown()
			return err
		}
		job, err := scheduler.NewJob(
			gocron.CronJob(expression, true),
			gocron.NewTask(h.performScheduled),
			gocron.WithName("automatic-vault-server-backup"),
		)
		if err != nil {
			_ = scheduler.Shutdown()
			return fmt.Errorf("schedule automatic server backup: %w", err)
		}
		h.job = job
	}
	scheduler.Start()
	return nil
}

func (h *Handler) Scheduler() gocron.Scheduler {
	return h.scheduler
}

func (h *Handler) StopScheduler() error {
	if h.scheduler == nil {
		return nil
	}
	return h.scheduler.Shutdown()
}

func (h *Handler) ConfigureSchedule(enabled bool, expression string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.scheduler == nil {
		return nil
	}
	if enabled {
		if err := ValidateDatabaseScope(h.config); err != nil {
			return err
		}
		if h.job != nil {
			job, err := h.scheduler.Update(
				h.job.ID(),
				gocron.CronJob(expression, true),
				gocron.NewTask(h.performScheduled),
				gocron.WithName("automatic-vault-server-backup"),
			)
			if err != nil {
				return err
			}
			h.job = job
			return nil
		}
		job, err := h.scheduler.NewJob(
			gocron.CronJob(expression, true),
			gocron.NewTask(h.performScheduled),
			gocron.WithName("automatic-vault-server-backup"),
		)
		if err != nil {
			return err
		}
		h.job = job
		return nil
	}
	if h.job == nil {
		return nil
	}
	if err := h.scheduler.RemoveJob(h.job.ID()); err != nil {
		return err
	}
	h.job = nil
	return nil
}

func (h *Handler) performScheduled() {
	if !h.runMu.TryLock() {
		h.audit(nil, "failure", "overlapping_backup_skipped")
		return
	}
	defer h.runMu.Unlock()
	h.audit(nil, "started", "")
	if h.deps.BeginMaintenance != nil {
		h.deps.BeginMaintenance(nil)
		defer h.deps.EndMaintenance()
	}
	createdAt := time.Now().UTC()
	metadata, err := h.deps.Metadata(createdAt)
	if err != nil {
		h.audit(nil, "failure", "metadata_error")
		return
	}
	if h.deps.CloseDatabases != nil {
		if err := h.deps.CloseDatabases(); err != nil {
			if h.deps.ReopenDatabases != nil {
				_ = h.deps.ReopenDatabases()
			}
			h.audit(nil, "failure", "database_close_error")
			return
		}
	}
	archivePath, backupErr := CreateWithMetadata(h.config.DataDir, h.config.BackupDir, metadata)
	if h.deps.ReopenDatabases != nil {
		reopenErr := h.deps.ReopenDatabases()
		if reopenErr != nil {
			h.audit(nil, "failure", "database_reopen_error")
			if h.deps.FailMaintenance != nil {
				h.deps.FailMaintenance()
			}
			return
		}
	}
	if backupErr != nil {
		h.audit(nil, "failure", "backup_error")
		return
	}
	s3Key, s3Err := h.copyToS3(archivePath)
	if s3Err != nil {
		h.audit(nil, "failure", "s3_copy_error")
		return
	}
	if h.deps.SaveSuccess != nil {
		_ = h.deps.SaveSuccess(time.Now().UTC())
	}
	_ = Prune(h.config.BackupDir, time.Now().UTC().Add(-Retention))
	detail := ""
	if s3Key != "" {
		detail = "s3_key=" + s3Key
	}
	h.audit(nil, "success", detail)
}
