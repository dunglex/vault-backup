package operator

import (
	"embed"
	"html/template"
	"io"
)

//go:embed operators.gohtml
var pageFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(pageFiles, "operators.gohtml"))

func RenderPage(w io.Writer) error {
	return RenderPageWithOptions(w, false)
}

func RenderPageWithOptions(w io.Writer, hasBackup bool) error {
	return pageTemplate.ExecuteTemplate(w, "operators.gohtml", map[string]bool{
		"IsAdmin":      true,
		"HasOperators": true,
		"HasBackup":    hasBackup,
	})
}
