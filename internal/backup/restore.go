package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Restore(backupDir, dataDir, name string) error {
	if filepath.Base(name) != name ||
		!strings.HasPrefix(name, "vault-server-backup-") ||
		!strings.HasSuffix(name, ".tar.gz") {
		return fmt.Errorf("invalid server backup name")
	}
	archivePath := filepath.Join(backupDir, name)
	info, err := os.Lstat(archivePath)
	if err != nil {
		return fmt.Errorf("inspect server backup: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("server backup is not a regular file")
	}

	parent := filepath.Dir(dataDir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create server data parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".vault-server-restore-*")
	if err != nil {
		return fmt.Errorf("create restore staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	checksums, err := extractDataArchive(archivePath, staging)
	if err != nil {
		return err
	}
	if len(checksums) == 0 {
		return fmt.Errorf("server backup contains no data")
	}

	rollbackName := ""
	if _, err := os.Lstat(dataDir); err == nil {
		rollback, err := os.MkdirTemp(parent, ".vault-server-restore-old-*")
		if err != nil {
			return fmt.Errorf("create restore rollback path: %w", err)
		}
		if err := os.Remove(rollback); err != nil {
			return fmt.Errorf("prepare restore rollback path: %w", err)
		}
		if err := os.Rename(dataDir, rollback); err != nil {
			return fmt.Errorf("preserve existing server data: %w", err)
		}
		rollbackName = rollback
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect existing server data: %w", err)
	}
	if err := os.Rename(staging, dataDir); err != nil {
		if rollbackName != "" {
			_ = os.Rename(rollbackName, dataDir)
		}
		return fmt.Errorf("install restored server data: %w", err)
	}
	if rollbackName != "" {
		if err := os.RemoveAll(rollbackName); err != nil {
			return fmt.Errorf("remove previous server data after restore: %w", err)
		}
	}
	return nil
}

func extractDataArchive(path, staging string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open server backup: %w", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("open compressed server backup: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	checksums := make(map[string]string)
	restored := make(map[string]string)
	manifestFound := false
	metadataFound := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read server backup: %w", err)
		}
		switch {
		case header.Name == "vault-server/metadata.json" && header.Typeflag == tar.TypeReg:
			metadataFound = true
			if header.Size < 0 || header.Size > 64*1024 {
				return nil, fmt.Errorf("invalid server backup metadata")
			}
			if _, err := io.Copy(io.Discard, io.LimitReader(reader, header.Size)); err != nil {
				return nil, fmt.Errorf("read server backup metadata: %w", err)
			}
		case header.Name == "vault-server/manifest.txt" && header.Typeflag == tar.TypeReg:
			manifestFound = true
			if header.Size < 0 || header.Size > 1024*1024 {
				return nil, fmt.Errorf("invalid server backup manifest")
			}
			data, err := io.ReadAll(io.LimitReader(reader, header.Size))
			if err != nil {
				return nil, fmt.Errorf("read server backup manifest: %w", err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 2 {
					continue
				}
				checksums[fields[1]] = fields[0]
			}
		case strings.HasPrefix(header.Name, "vault-server/data/") && header.Typeflag == tar.TypeReg:
			relative := strings.TrimPrefix(header.Name, "vault-server/data/")
			if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "\\") ||
				strings.ContainsAny(relative, "\r\n") {
				return nil, fmt.Errorf("invalid server backup data path")
			}
			clean := filepath.Clean(filepath.FromSlash(relative))
			if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("invalid server backup data path")
			}
			destination := filepath.Join(staging, clean)
			if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
				return nil, fmt.Errorf("create restored data directory: %w", err)
			}
			output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return nil, fmt.Errorf("create restored data file: %w", err)
			}
			digest := sha256.New()
			_, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(reader, header.Size))
			closeErr := output.Close()
			if copyErr != nil {
				return nil, fmt.Errorf("restore server data file: %w", copyErr)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("close restored server data file: %w", closeErr)
			}
			actual := hex.EncodeToString(digest.Sum(nil))
			restored[filepath.ToSlash(relative)] = actual
		case header.Typeflag != tar.TypeDir:
			return nil, fmt.Errorf("unsupported server backup entry: %q", header.Name)
		}
	}
	if !metadataFound || !manifestFound {
		return nil, fmt.Errorf("server backup is missing metadata or manifest")
	}
	for relative, actual := range restored {
		expected, ok := checksums["data/"+relative]
		if !ok {
			return nil, fmt.Errorf("server backup manifest missing data file: %q", relative)
		}
		if actual != expected {
			return nil, fmt.Errorf("restored server data checksum mismatch: %q", relative)
		}
	}
	for name := range checksums {
		if name != "metadata.json" && !strings.HasPrefix(name, "data/") {
			return nil, fmt.Errorf("invalid server backup manifest entry: %q", name)
		}
		if strings.HasPrefix(name, "data/") {
			relative := strings.TrimPrefix(name, "data/")
			if _, ok := restored[relative]; !ok {
				return nil, fmt.Errorf("server backup manifest references missing data file: %q", relative)
			}
		}
	}
	return checksums, nil
}
