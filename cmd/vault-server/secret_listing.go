package main

import (
	"database/sql"
	"errors"
	"strings"
)

const secretListingSchema = `
	CREATE TABLE IF NOT EXISTS secret_listing (
		parent_path TEXT NOT NULL,
		child_key TEXT NOT NULL,
		ref_count INTEGER NOT NULL CHECK (ref_count > 0),
		PRIMARY KEY (parent_path, child_key)
	);
	CREATE TABLE IF NOT EXISTS secret_listing_migrations (
		name TEXT PRIMARY KEY
	);
`

func initializeSecretListingCache(db *sql.DB) error {
	if _, err := db.Exec(secretListingSchema); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var initialized bool
	if err := tx.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM secret_listing_migrations WHERE name = 'secret-listing-v1')",
	).Scan(&initialized); err != nil {
		return err
	}
	if initialized {
		return nil
	}

	rows, err := tx.Query(`
		SELECT s.path
		FROM secrets s
		JOIN secret_versions v
		  ON v.path = s.path AND v.version = s.current_version
		WHERE v.deleted_at IS NULL AND v.destroyed_at IS NULL
	`)
	if err != nil {
		return err
	}
	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, path)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, path := range paths {
		if err := updateSecretListingPath(tx, path, 1); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		"INSERT INTO secret_listing_migrations(name) VALUES ('secret-listing-v1')",
	); err != nil {
		return err
	}
	return tx.Commit()
}

func currentSecretIsVisible(tx *sql.Tx, path string) (bool, error) {
	var visible bool
	err := tx.QueryRow(`
		SELECT EXISTS(
			SELECT 1
			FROM secrets s
			JOIN secret_versions v
			  ON v.path = s.path AND v.version = s.current_version
			WHERE s.path = ?
			  AND v.deleted_at IS NULL
			  AND v.destroyed_at IS NULL
		)`, path,
	).Scan(&visible)
	return visible, err
}

func syncSecretListingVisibility(tx *sql.Tx, path string, wasVisible bool) error {
	isVisible, err := currentSecretIsVisible(tx, path)
	if err != nil {
		return err
	}
	if wasVisible == isVisible {
		return nil
	}
	if isVisible {
		return updateSecretListingPath(tx, path, 1)
	}
	return updateSecretListingPath(tx, path, -1)
}

func updateSecretListingPath(tx *sql.Tx, path string, delta int) error {
	if delta != 1 && delta != -1 {
		return errors.New("invalid secret listing update")
	}
	parts := strings.Split(path, "/")
	if path == "" {
		return errors.New("invalid secret listing path")
	}
	for _, part := range parts {
		if part == "" {
			return errors.New("invalid secret listing path")
		}
	}

	parent := ""
	for index, part := range parts {
		key := part
		if index < len(parts)-1 {
			key += "/"
		}
		if delta > 0 {
			if _, err := tx.Exec(`
				INSERT INTO secret_listing(parent_path, child_key, ref_count)
				VALUES (?, ?, 1)
				ON CONFLICT(parent_path, child_key)
				DO UPDATE SET ref_count = ref_count + 1`,
				parent, key,
			); err != nil {
				return err
			}
		} else {
			result, err := tx.Exec(`
				DELETE FROM secret_listing
				WHERE parent_path = ? AND child_key = ? AND ref_count = 1`,
				parent, key,
			)
			if err != nil {
				return err
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if affected == 0 {
				result, err = tx.Exec(`
					UPDATE secret_listing
					SET ref_count = ref_count - 1
					WHERE parent_path = ? AND child_key = ? AND ref_count > 1`,
					parent, key,
				)
				if err != nil {
					return err
				}
				affected, err = result.RowsAffected()
				if err != nil {
					return err
				}
				if affected == 0 {
					return errors.New("secret listing cache is inconsistent")
				}
			}
		}
		if parent == "" {
			parent = part
		} else {
			parent += "/" + part
		}
	}
	return nil
}
