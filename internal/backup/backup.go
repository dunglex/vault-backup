package backup

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"
)

const (
	EnabledSetting        = "backup_extension_enabled"
	AutomaticSetting      = "automatic_server_backup"
	CronSetting           = "server_backup_cron"
	LastSuccessSetting    = "server_backup_last_success"
	S3EnabledSetting      = "s3_backup_enabled"
	S3EndpointSetting     = "s3_backup_endpoint"
	S3RegionSetting       = "s3_backup_region"
	S3BucketSetting       = "s3_backup_bucket"
	S3PrefixSetting       = "s3_backup_prefix"
	S3AccessKeySetting    = "s3_backup_access_key_id"
	S3SecretKeySetting    = "s3_backup_secret_access_key"
	S3SessionTokenSetting = "s3_backup_session_token"
	S3PathStyleSetting    = "s3_backup_path_style"
	DefaultCron           = "0 0 2 * * *"
	Retention             = 30 * 24 * time.Hour
)

type Config struct {
	DataDir        string
	BackupDir      string
	DBPath         string
	SecretsDBPath  string
	OperatorDBPath string
	AuditDBPath    string
	MasterKey      []byte
	SecretsKey     []byte
	OperatorKey    []byte
	AllowPlaintext bool
}

type Metadata struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Operators int       `json:"operators"`
	Secrets   int       `json:"secrets"`
	APITokens int       `json:"api_tokens"`
}

type Summary struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Operators *int      `json:"operators"`
	Secrets   *int      `json:"secrets"`
	APITokens *int      `json:"api_tokens"`
}

func ReadExtensionEnabled(db *sql.DB) (bool, error) {
	var value string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", EnabledSetting).Scan(&value)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read backup extension setting: %w", err)
	}
	if value != "true" && value != "false" {
		return false, fmt.Errorf("invalid %s setting", EnabledSetting)
	}
	return value == "true", nil
}

func ReadSettings(db *sql.DB) (bool, string, string, error) {
	enabled := false
	var enabledValue string
	err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", AutomaticSetting).Scan(&enabledValue)
	if err != nil && err != sql.ErrNoRows {
		return false, "", "", fmt.Errorf("read automatic server backup setting: %w", err)
	}
	if err == nil {
		if enabledValue != "true" && enabledValue != "false" {
			return false, "", "", fmt.Errorf("invalid %s setting", AutomaticSetting)
		}
		enabled = enabledValue == "true"
	}

	cronExpression := DefaultCron
	var configuredCron string
	err = db.QueryRow("SELECT value FROM server_settings WHERE key = ?", CronSetting).Scan(&configuredCron)
	if err != nil && err != sql.ErrNoRows {
		return false, "", "", fmt.Errorf("read server backup cron setting: %w", err)
	}
	if err == nil && strings.TrimSpace(configuredCron) != "" {
		cronExpression = configuredCron
	}

	lastSuccess := ""
	err = db.QueryRow("SELECT value FROM server_settings WHERE key = ?", LastSuccessSetting).Scan(&lastSuccess)
	if err != nil && err != sql.ErrNoRows {
		return false, "", "", fmt.Errorf("read last server backup time: %w", err)
	}
	return enabled, cronExpression, lastSuccess, nil
}

func ReadS3Config(db *sql.DB) (S3Config, error) {
	config := S3Config{}
	values := map[string]*string{
		S3EndpointSetting:     &config.Endpoint,
		S3RegionSetting:       &config.Region,
		S3BucketSetting:       &config.Bucket,
		S3PrefixSetting:       &config.Prefix,
		S3AccessKeySetting:    &config.AccessKeyID,
		S3SecretKeySetting:    &config.SecretAccessKey,
		S3SessionTokenSetting: &config.SessionToken,
		S3PathStyleSetting:    new(string),
		S3EnabledSetting:      new(string),
	}
	for key, destination := range values {
		var value string
		err := db.QueryRow("SELECT value FROM server_settings WHERE key = ?", key).Scan(&value)
		if err != nil && err != sql.ErrNoRows {
			return S3Config{}, fmt.Errorf("read %s: %w", key, err)
		}
		if err == nil {
			*destination = value
		}
	}
	config.Enabled = values[S3EnabledSetting] != nil && *values[S3EnabledSetting] == "true"
	if pathStyleValue := *values[S3PathStyleSetting]; pathStyleValue == "true" {
		config.ForcePathStyle = true
	}
	return config, nil
}

func ValidateCron(expression string) error {
	fields := strings.Fields(expression)
	if len(fields) != 6 || strings.ContainsAny(expression, "\r\n") {
		return fmt.Errorf("backup schedule must be a six-field cron expression (second minute hour day month weekday)")
	}
	scheduler, err := gocron.NewScheduler(gocron.WithLocation(time.UTC))
	if err != nil {
		return fmt.Errorf("create backup schedule validator: %w", err)
	}
	_, jobErr := scheduler.NewJob(gocron.CronJob(expression, true), gocron.NewTask(func() {}))
	shutdownErr := scheduler.Shutdown()
	if jobErr != nil {
		return fmt.Errorf("invalid backup cron expression: %w", jobErr)
	}
	if shutdownErr != nil {
		return fmt.Errorf("stop backup schedule validator: %w", shutdownErr)
	}
	return nil
}

func ValidateDatabaseScope(config Config) error {
	if config.DataDir == "" {
		return nil
	}
	dataDir, err := filepath.EvalSymlinks(config.DataDir)
	if err != nil {
		return fmt.Errorf("resolve backup data directory: %w", err)
	}
	paths := []string{config.DBPath, config.DBPath + ".key", config.SecretsDBPath, config.SecretsDBPath + ".key", config.AuditDBPath}
	if config.OperatorDBPath != "" {
		paths = append(paths, config.OperatorDBPath, config.OperatorDBPath+".key")
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
				if parentErr != nil {
					return fmt.Errorf("resolve database directory for scheduled backup: %w", parentErr)
				}
				resolved = filepath.Join(parent, filepath.Base(path))
			} else {
				return fmt.Errorf("resolve database path for scheduled backup: %w", err)
			}
		}
		relative, err := filepath.Rel(dataDir, resolved)
		if err != nil {
			return fmt.Errorf("compare database path with backup data directory: %w", err)
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("scheduled backups require all database files to be inside data directory %q", dataDir)
		}
	}
	return nil
}

func List(directory string) ([]Summary, error) {
	entries, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	backups := make([]Summary, 0)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "vault-server-backup-") || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		summary, err := ReadSummary(path, entry.Name(), info.ModTime())
		if err != nil {
			return nil, err
		}
		backups = append(backups, summary)
	}
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})
	return backups, nil
}

func ReadSummary(path, name string, modifiedAt time.Time) (Summary, error) {
	summary := Summary{Name: name, CreatedAt: modifiedAt.UTC()}
	file, err := os.Open(path)
	if err != nil {
		return Summary{}, fmt.Errorf("open server backup: %w", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return Summary{}, fmt.Errorf("open compressed server backup: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return summary, nil
		}
		if err != nil {
			return Summary{}, fmt.Errorf("read server backup entry: %w", err)
		}
		if header.Name == "vault-server/metadata.json" && header.Typeflag == tar.TypeReg {
			const maxMetadataSize = 64 * 1024
			if header.Size < 0 || header.Size > maxMetadataSize {
				return Summary{}, fmt.Errorf("server backup metadata is too large")
			}
			data, err := io.ReadAll(io.LimitReader(reader, maxMetadataSize+1))
			if err != nil {
				return Summary{}, fmt.Errorf("read server backup metadata: %w", err)
			}
			var metadata Metadata
			if err := json.Unmarshal(data, &metadata); err != nil {
				return Summary{}, fmt.Errorf("decode server backup metadata: %w", err)
			}
			if metadata.Operators < 0 || metadata.Secrets < 0 || metadata.APITokens < 0 || metadata.CreatedAt.IsZero() {
				return Summary{}, fmt.Errorf("server backup metadata contains invalid values")
			}
			summary.CreatedAt = metadata.CreatedAt.UTC()
			summary.Operators = &metadata.Operators
			summary.Secrets = &metadata.Secrets
			summary.APITokens = &metadata.APITokens
			return summary, nil
		}
	}
}
