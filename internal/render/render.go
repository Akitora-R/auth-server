package render

import (
	"html/template"
	"net/http"
)

var tpl = template.Must(template.New("").ParseGlob("template/*"))

func Html(w http.ResponseWriter, tplName string, code int, data any) error {
	w.WriteHeader(code)
	return tpl.ExecuteTemplate(w, tplName, data)
}
