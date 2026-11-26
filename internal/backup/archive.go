package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func Create(dataDir, backupDir string, now time.Time) (string, error) {
	return CreateWithMetadata(dataDir, backupDir, Metadata{CreatedAt: now.UTC()})
}

func CreateWithMetadata(dataDir, backupDir string, metadata Metadata) (string, error) {
	source, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return "", fmt.Errorf("resolve server data directory: %w", err)
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return "", fmt.Errorf("inspect server data directory: %w", err)
	}
	if !sourceInfo.IsDir() {
		return "", fmt.Errorf("server data path %q is not a directory", source)
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("create server backup directory: %w", err)
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		return "", fmt.Errorf("restrict server backup directory permissions: %w", err)
	}
	backupDir, err = filepath.EvalSymlinks(backupDir)
	if err != nil {
		return "", fmt.Errorf("resolve server backup directory: %w", err)
	}
	relativeBackup, err := filepath.Rel(source, backupDir)
	if err != nil {
		return "", fmt.Errorf("compare server data and backup directories: %w", err)
	}
	if relativeBackup == "." {
		return "", fmt.Errorf("server backup directory must differ from the data directory")
	}
	backupInsideData := relativeBackup != ".." && !strings.HasPrefix(relativeBackup, ".."+string(filepath.Separator))

	var files []string
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk server data directory: %w", walkErr)
		}
		if path == source {
			return nil
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve server data entry: %w", err)
		}
		if backupInsideData && (relative == relativeBackup || strings.HasPrefix(relative, relativeBackup+string(filepath.Separator))) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect server data entry: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("server data directory contains a symbolic link: %q", relative)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("server data directory contains a non-regular file: %q", relative)
		}
		if strings.ContainsAny(filepath.ToSlash(relative), "\r\n\\") {
			return fmt.Errorf("server data file path cannot be represented in the backup manifest: %q", relative)
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("server data directory contains no files")
	}
	sort.Strings(files)
	archivePath := filepath.Join(backupDir, "vault-server-backup-"+metadata.CreatedAt.UTC().Format("20060102-150405.000000000")+".tar.gz")
	metadata.Name = filepath.Base(archivePath)
	metadata.CreatedAt = metadata.CreatedAt.UTC()
	if err := writeArchive(source, archivePath, files, metadata); err != nil {
		return "", err
	}
	return archivePath, nil
}

func writeArchive(source, archivePath string, files []string, metadata Metadata) (resultErr error) {
	temp, err := os.CreateTemp(filepath.Dir(archivePath), ".vault-server-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary server backup: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if resultErr != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("restrict temporary backup permissions: %w", err)
	}

	gz := gzip.NewWriter(temp)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
		return fmt.Errorf("write archive root directory: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/data/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
		return fmt.Errorf("write archive data directory: %w", err)
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode server backup metadata: %w", err)
	}
	metadataBytes = append(metadataBytes, '\n')
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/metadata.json", Mode: 0600, Size: int64(len(metadataBytes))}); err != nil {
		return fmt.Errorf("write server backup metadata header: %w", err)
	}
	if _, err := tw.Write(metadataBytes); err != nil {
		return fmt.Errorf("write server backup metadata: %w", err)
	}
	checksums := map[string]string{"metadata.json": fmt.Sprintf("%x", sha256.Sum256(metadataBytes))}
	directories := make(map[string]struct{})
	for _, path := range files {
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve server data file: %w", err)
		}
		relative = filepath.ToSlash(filepath.Dir(relative))
		for relative != "." && relative != "" {
			directories[relative] = struct{}{}
			relative = filepath.ToSlash(filepath.Dir(relative))
		}
	}
	directoryNames := make([]string, 0, len(directories))
	for directory := range directories {
		directoryNames = append(directoryNames, directory)
	}
	sort.Strings(directoryNames)
	for _, directory := range directoryNames {
		name := filepath.ToSlash(filepath.Join("vault-server", "data", directory)) + "/"
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
			return fmt.Errorf("write backup directory %q: %w", name, err)
		}
	}
	for _, path := range files {
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve server data file: %w", err)
		}
		if err := addFile(tw, path, filepath.ToSlash(relative), checksums); err != nil {
			return err
		}
	}
	if err := writeManifest(tw, checksums, metadata.CreatedAt); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("finish backup tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("finish compressed server backup: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync server backup: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close server backup: %w", err)
	}
	if err := os.Rename(tempPath, archivePath); err != nil {
		return fmt.Errorf("install server backup: %w", err)
	}
	return os.Chmod(archivePath, 0600)
}

func addFile(tw *tar.Writer, path, relative string, checksums map[string]string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect server data file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("server data entry changed during backup: %q", relative)
	}
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open server data file: %w", err)
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened server data file: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("recheck server data file: %w", err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return fmt.Errorf("server data entry changed during backup: %q", relative)
	}
	name := filepath.ToSlash(filepath.Join("vault-server", "data", relative))
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: opened.Size(), ModTime: opened.ModTime()}); err != nil {
		return fmt.Errorf("write server backup file header: %w", err)
	}
	digest := sha256.New()
	if copied, err := io.CopyN(io.MultiWriter(tw, digest), input, opened.Size()); err != nil {
		return fmt.Errorf("write server backup file: %w", err)
	} else if copied != opened.Size() {
		return fmt.Errorf("server data file changed during backup: %q", relative)
	}
	checksums[filepath.ToSlash(filepath.Join("data", relative))] = fmt.Sprintf("%x", digest.Sum(nil))
	return nil
}

func writeManifest(tw *tar.Writer, checksums map[string]string, createdAt time.Time) error {
	paths := make([]string, 0, len(checksums))
	for path := range checksums {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var contents strings.Builder
	fmt.Fprintf(&contents, "# Vault server data backup\n# Created-UTC: %s\n", createdAt.Format(time.RFC3339))
	for _, path := range paths {
		fmt.Fprintf(&contents, "%s  %s\n", checksums[path], path)
	}
	data := contents.String()
	if err := tw.WriteHeader(&tar.Header{Name: "vault-server/manifest.txt", Mode: 0600, Size: int64(len(data))}); err != nil {
		return fmt.Errorf("write server backup manifest header: %w", err)
	}
	_, err := io.WriteString(tw, data)
	return err
}

func Prune(directory string, cutoff time.Time) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read server backup directory: %w", err)
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "vault-server-backup-") || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect backup %q: %w", entry.Name(), err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil {
			failures = append(failures, fmt.Errorf("remove expired backup %q: %w", entry.Name(), err))
		}
	}
	return errors.Join(failures...)
}
