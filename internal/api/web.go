package api

import (
	"io/fs"
	"net/http"
	"strings"

	webui "github.com/svinson1121/vectorcore-mcx/web"
)

func uiHandler() http.Handler {
	sub, err := fs.Sub(webui.FS, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:2rem">` +
				`<h2>VectorCore MCX</h2><p>UI not built. Run <code>make ui</code> then rebuild the binary.</p>` +
				`<p><a href="/api/v1/docs" style="color:#58a6ff">API Docs</a></p></body></html>`))
		})
	}

	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/ui")
		if path == "" || path == "/" {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		f, err := sub.Open(strings.TrimPrefix(path, "/"))
		if err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/ui/index.html"
			http.StripPrefix("/ui", fileServer).ServeHTTP(w, r2)
			return
		}
		f.Close()
		http.StripPrefix("/ui", fileServer).ServeHTTP(w, r)
	})
}
