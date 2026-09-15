// Package proxy implements the OpenAI-compatible HTTP surface that sits in
// front of a model provider.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Anwesha33/pii-shield/internal/config"
	"github.com/Anwesha33/pii-shield/internal/detect"
	"github.com/Anwesha33/pii-shield/internal/metrics"
	"github.com/Anwesha33/pii-shield/internal/policy"
	"github.com/Anwesha33/pii-shield/internal/redact"
	"github.com/Anwesha33/pii-shield/internal/vault"
)

// Handler proxies chat-completion requests, redacting on the way out and
// re-hydrating on the way back.
type Handler struct {
	cfg    *config.Config
	red    *redact.Redactor
	client *http.Client
}

func New(cfg *config.Config) *Handler {
	pol := cfg.Policy()
	return &Handler{
		cfg:    cfg,
		red:    redact.New(detect.NewEngineWith(pol.EnabledTypes()), pol),
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.fail(w, http.StatusBadRequest, "read_error", "could not read request body")
		return
	}

	// The payload is kept as a generic map rather than a typed struct so that
	// provider-specific fields the proxy knows nothing about survive the round
	// trip untouched. A typed struct would silently drop them, and a proxy that
	// quietly eats parameters is worse than no proxy.
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		h.fail(w, http.StatusBadRequest, "bad_json", "request body is not valid JSON")
		return
	}

	v := vault.New()
	start := time.Now()
	result, err := h.redactPayload(payload, v)
	metrics.RedactionSeconds.Observe(time.Since(start).Seconds())

	if err != nil {
		var blocked *redact.BlockedError
		if errors.As(err, &blocked) {
			metrics.RequestsTotal.WithLabelValues("blocked").Inc()
			metrics.EntitiesRedacted.WithLabelValues(string(blocked.Type), string(policy.Block)).Add(float64(blocked.Count))
			h.fail(w, http.StatusUnprocessableEntity, "blocked_by_policy", blocked.Error())
			return
		}
		metrics.RequestsTotal.WithLabelValues("error").Inc()
		h.fail(w, http.StatusInternalServerError, "redaction_failed", err.Error())
		return
	}

	for t, n := range result.Counts {
		metrics.EntitiesRedacted.WithLabelValues(string(t), "applied").Add(float64(n))
	}
	if h.cfg.LogDecisions {
		// Only types and counts are logged. Logging the values themselves would
		// recreate, in the proxy's own log file, exactly the exposure the proxy
		// exists to prevent.
		log.Printf("request redacted: %s (%d distinct values tokenized)", result.Summary(), v.Len())
	}

	streaming, _ := payload["stream"].(bool)
	upstreamBody, err := json.Marshal(payload)
	if err != nil {
		h.fail(w, http.StatusInternalServerError, "marshal_failed", err.Error())
		return
	}

	resp, err := h.forward(r, upstreamBody)
	if err != nil {
		metrics.RequestsTotal.WithLabelValues("upstream_error").Inc()
		h.fail(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
		return
	}
	defer resp.Body.Close()

	if streaming {
		h.streamResponse(w, resp, v)
		return
	}
	h.bufferedResponse(w, resp, v)
}

// redactPayload rewrites every message body in place.
func (h *Handler) redactPayload(payload map[string]any, v *vault.Vault) (*redact.Result, error) {
	msgs, ok := payload["messages"].([]any)
	if !ok {
		return &redact.Result{Counts: map[detect.EntityType]int{}}, nil
	}

	combined := &redact.Result{Counts: map[detect.EntityType]int{}}
	for _, raw := range msgs {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			res, err := h.red.Redact(content, v)
			if err != nil {
				return nil, err
			}
			msg["content"] = res.Text
			merge(combined, res)

		case []any:
			// Multimodal content: an array of typed parts. Only text parts are
			// scanned; image parts are passed through untouched, which is an
			// explicit limitation rather than an oversight (see README).
			for _, p := range content {
				part, ok := p.(map[string]any)
				if !ok {
					continue
				}
				text, ok := part["text"].(string)
				if !ok {
					continue
				}
				res, err := h.red.Redact(text, v)
				if err != nil {
					return nil, err
				}
				part["text"] = res.Text
				merge(combined, res)
			}
		}
	}
	return combined, nil
}

func merge(dst, src *redact.Result) {
	dst.Decisions = append(dst.Decisions, src.Decisions...)
	for t, n := range src.Counts {
		dst.Counts[t] += n
	}
}

// forward sends the redacted payload upstream.
func (h *Handler) forward(orig *http.Request, body []byte) (*http.Response, error) {
	url := strings.TrimRight(h.cfg.Upstream, "/") + "/chat/completions"
	key := h.cfg.UpstreamKey()
	if h.cfg.UpstreamAuthStyle == "query" && key != "" {
		url += "?key=" + key
	}

	req, err := http.NewRequestWithContext(orig.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.cfg.UpstreamAuthStyle == "bearer" && key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	start := time.Now()
	resp, err := h.client.Do(req)
	metrics.UpstreamSeconds.Observe(time.Since(start).Seconds())
	return resp, err
}

// bufferedResponse handles a non-streaming completion.
func (h *Handler) bufferedResponse(w http.ResponseWriter, resp *http.Response, v *vault.Vault) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.fail(w, http.StatusBadGateway, "upstream_read_failed", err.Error())
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// Pass an unparseable upstream body through verbatim rather than
		// masking the provider's own error behind one of ours.
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		w.Write(raw)
		return
	}

	h.rehydrateChoices(parsed, v)

	out, _ := json.Marshal(parsed)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(out)

	if resp.StatusCode >= 400 {
		metrics.RequestsTotal.WithLabelValues("upstream_status_error").Inc()
	} else {
		metrics.RequestsTotal.WithLabelValues("ok").Inc()
	}
}

// rehydrateChoices restores originals in every choice and scans for leaks.
func (h *Handler) rehydrateChoices(parsed map[string]any, v *vault.Vault) {
	choices, ok := parsed["choices"].([]any)
	if !ok {
		return
	}
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			continue
		}
		text, ok := msg["content"].(string)
		if !ok {
			continue
		}
		if h.cfg.ScanResponses {
			for _, leak := range redact.ScanOutput(text, v) {
				metrics.LeaksDetected.WithLabelValues(string(leak.Type)).Inc()
				log.Printf("WARNING: response contained a %s not present in the request", leak.Type)
			}
		}
		msg["content"] = redact.Rehydrate(text, v)
	}
}

// streamResponse relays an SSE stream, re-hydrating content deltas as they pass.
func (h *Handler) streamResponse(w http.ResponseWriter, resp *http.Response, v *vault.Vault) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.fail(w, http.StatusInternalServerError, "streaming_unsupported", "response writer cannot flush")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)

	rewriter := newStreamRewriter(v)
	scanner := bufio.NewScanner(resp.Body)
	// SSE frames can carry a whole message; the default 64KB token limit is
	// raised so a long line cannot truncate the stream.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			fmt.Fprintf(w, "%s\n", line)
			flusher.Flush()
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			if tail := rewriter.Flush(); tail != "" {
				// Anything still held back is emitted as a final synthetic
				// delta so that no content is lost at end of stream.
				fmt.Fprintf(w, "data: %s\n\n", syntheticDelta(tail))
			}
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			break
		}

		var frame map[string]any
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			fmt.Fprintf(w, "%s\n", line)
			flusher.Flush()
			continue
		}
		rewriteStreamFrame(frame, rewriter)

		out, _ := json.Marshal(frame)
		fmt.Fprintf(w, "data: %s\n\n", out)
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("stream ended with error: %v", err)
		metrics.RequestsTotal.WithLabelValues("stream_error").Inc()
		return
	}
	metrics.RequestsTotal.WithLabelValues("ok").Inc()
}

// rewriteStreamFrame replaces the content delta inside one SSE frame.
func rewriteStreamFrame(frame map[string]any, rewriter *streamRewriter) {
	choices, ok := frame["choices"].([]any)
	if !ok {
		return
	}
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}
		text, ok := delta["content"].(string)
		if !ok {
			continue
		}
		delta["content"] = rewriter.Write(text)
	}
}

// syntheticDelta builds a minimal SSE frame carrying trailing content.
func syntheticDelta(text string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"delta": map[string]any{"content": text}, "index": 0}},
	})
	return string(b)
}

// fail writes an OpenAI-shaped error so that existing client SDKs surface it
// the same way they surface a provider error.
func (h *Handler) fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "pii_shield_error",
			"code":    code,
		},
	})
}
