package server

import (
	"fmt"
	"net/http"
	"os"
)

// Run serves the API on addr.
func Run(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "db configured: %v\n", os.Getenv("DB_PASSWORD") != "")
	})
	return http.ListenAndServe(addr, mux)
}
