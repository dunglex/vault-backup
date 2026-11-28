package backup

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderPageIncludesAvailableAdminNavigation(t *testing.T) {
	var page bytes.Buffer
	if err := RenderPageWithOptions(&page, true); err != nil {
		t.Fatal(err)
	}

	for _, marker := range []string{
		`href="/mounts.html"`,
		`href="/operators.html"`,
		`href="/backup.html"`,
		`href="/security.html"`,
	} {
		if !strings.Contains(page.String(), marker) {
			t.Errorf("backup page missing %q", marker)
		}
	}
}

func TestRenderPageUsesDialogForScheduledBackupSettings(t *testing.T) {
	var page bytes.Buffer
	if err := RenderPageWithOptions(&page, false); err != nil {
		t.Fatal(err)
	}

	for _, marker := range []string{
		`id="openBackupSettings"`,
		`<dialog id="backupSettingsDialog"`,
		`id="backupSettingsForm"`,
		`id="lastServerBackup"`,
		`<th>File size</th>`,
		`formatFileSize(backup.size_bytes)`,
		`backupSettingsDialog.showModal()`,
	} {
		if !strings.Contains(page.String(), marker) {
			t.Errorf("backup page missing %q", marker)
		}
	}
}

func TestRenderPageUsesDialogForS3Settings(t *testing.T) {
	var page bytes.Buffer
	if err := RenderPageWithOptions(&page, false); err != nil {
		t.Fatal(err)
	}

	for _, marker := range []string{
		`id="openS3Settings"`,
		`<dialog id="s3SettingsDialog"`,
		`id="s3SettingsForm"`,
		`id="testS3Connection"`,
		`s3SettingsDialog.showModal()`,
	} {
		if !strings.Contains(page.String(), marker) {
			t.Errorf("backup page missing %q", marker)
		}
	}
}

func TestBackupActionsAreInServerBackupsHeader(t *testing.T) {
	var page bytes.Buffer
	if err := RenderPageWithOptions(&page, false); err != nil {
		t.Fatal(err)
	}
	rendered := page.String()
	header := strings.Index(rendered, `<h2 class="section-label">Server backups</h2>`)
	table := strings.Index(rendered, `<table>`)
	if header < 0 || table < 0 || header >= table {
		t.Fatal("server backups header or table is missing")
	}
	for _, action := range []string{
		`id="openBackupSettings"`,
		`id="openS3Settings"`,
		`id="createServerBackup"`,
	} {
		position := strings.Index(rendered, action)
		if position < header || position > table {
			t.Errorf("%s is not in the server backups header", action)
		}
	}
	if strings.Contains(rendered, `<h2 class="section-label">Scheduled backup</h2>`) ||
		strings.Contains(rendered, `<h2 class="section-label">S3 copy</h2>`) {
		t.Error("scheduled backup and S3 copy sections should be removed")
	}
}
