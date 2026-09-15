// Package metrics exposes the proxy's Prometheus instrumentation.
//
// The metric set is chosen to answer the three questions an operator actually
// asks about a redaction proxy: is it leaking, is it over-redacting, and is it
// slowing requests down.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	// RequestsTotal counts proxied requests by outcome.
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_requests_total",
		Help: "Proxied requests by outcome.",
	}, []string{"outcome"})

	// EntitiesRedacted counts acted-on entities by type and action. Watching
	// this per type is how over-redaction gets caught in production: a sudden
	// spike in one entity class usually means a detector started matching
	// something it should not.
	EntitiesRedacted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_entities_redacted_total",
		Help: "Entities acted on, by type and action.",
	}, []string{"type", "action"})

	// LeaksDetected counts entities found in a response that were absent from
	// the request. Any non-zero value here is worth an alert.
	LeaksDetected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_response_leaks_total",
		Help: "Entities detected in responses that were not present in the request.",
	}, []string{"type"})

	// RedactionSeconds measures the proxy's own overhead, excluding upstream
	// time. This is the number that decides whether anyone is willing to put
	// the proxy in their request path.
	RedactionSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "piishield_redaction_duration_seconds",
		Help:    "Time spent detecting and redacting, excluding upstream latency.",
		Buckets: []float64{0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05},
	})

	// UpstreamSeconds measures time spent waiting on the model provider, kept
	// separate so proxy overhead and provider latency are never conflated.
	UpstreamSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "piishield_upstream_duration_seconds",
		Help:    "Time spent waiting on the upstream provider.",
		Buckets: prometheus.DefBuckets,
	})
)

// MustRegister registers every collector with the default registry.
func MustRegister() {
	prometheus.MustRegister(
		RequestsTotal,
		EntitiesRedacted,
		LeaksDetected,
		RedactionSeconds,
		UpstreamSeconds,
	)
}

// Handler serves the Prometheus scrape endpoint.
func Handler() http.Handler { return promhttp.Handler() }
