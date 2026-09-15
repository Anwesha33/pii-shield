// Command proxy runs the PIIShield redaction proxy.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Anwesha33/pii-shield/internal/config"
	"github.com/Anwesha33/pii-shield/internal/metrics"
	"github.com/Anwesha33/pii-shield/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "", "path to config.yaml (optional; defaults are safe)")
	listen := flag.String("listen", "", "override the listen address")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if cfg.UpstreamKey() == "" {
		log.Printf("warning: %s is empty; upstream calls will likely be rejected", cfg.UpstreamAPIKeyEnv)
	}

	metrics.MustRegister()

	mux := http.NewServeMux()
	mux.Handle("/v1/chat/completions", proxy.New(cfg))
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "upstream": cfg.Upstream})
	})

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
		// A read timeout well above the upstream timeout, because a streaming
		// client legitimately holds the connection open for the whole response.
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown: in-flight completions can take tens of seconds, and
	// killing them mid-stream would hand the caller a truncated response with
	// no way to tell it apart from a model that simply stopped early.
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("shutting down; waiting for in-flight requests")
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout+5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
		close(done)
	}()

	log.Printf("pii-shield listening on %s, forwarding to %s", cfg.Listen, cfg.Upstream)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
	<-done
	log.Println("stopped")
}
