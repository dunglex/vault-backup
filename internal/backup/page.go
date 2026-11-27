package backup

import (
	"embed"
	"html/template"
	"io"
)

//go:embed backup.gohtml
var pageFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(pageFiles, "backup.gohtml"))

func RenderPage(w io.Writer) error {
	return RenderPageWithOptions(w, false)
}

func RenderPageWithOptions(w io.Writer, hasOperators bool) error {
	return pageTemplate.ExecuteTemplate(w, "backup.gohtml", map[string]bool{
		"IsAdmin":      true,
		"HasOperators": hasOperators,
		"HasBackup":    true,
	})
}
