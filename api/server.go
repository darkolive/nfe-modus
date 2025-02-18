package main

import (
	"fmt"
	"net/http"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"nfe-modus/api/functions/auth"
)

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from the frontend
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func StartServer() error {
	mux := http.NewServeMux()

	// Initialize routes
	auth.InitRoutes(mux, connection)

	// Wrap the mux with CORS middleware
	handler := enableCORS(mux)

	// Start server
	addr := ":8686"
	console.Info(fmt.Sprintf("Starting server on %s", addr))
	return http.ListenAndServe(addr, handler)
}
