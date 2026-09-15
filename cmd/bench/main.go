// Command bench scores the detector set against the labeled corpus and reports
// per-entity precision, recall and F1 plus the proxy's redaction latency.
//
// Two matching modes are reported because they answer different questions:
//
//	strict  - the detected span must equal the labeled span exactly. This is
//	          what matters for redaction correctness: a span that is one byte
//	          short leaves a digit of the card number in the outbound prompt.
//	relaxed - any overlap of the same entity type counts. Useful for telling
//	          "missed it entirely" apart from "found it but drew the boundary
//	          differently", which are very different bugs.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Anwesha33/pii-shield/internal/detect"
)

type labeledEntity struct {
	Type  string `json:"type"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Value string `json:"value"`
}

type document struct {
	ID       string          `json:"id"`
	Text     string          `json:"text"`
	Entities []labeledEntity `json:"entities"`
}

type tally struct{ TP, FP, FN int }

func (t tally) precision() float64 {
	if t.TP+t.FP == 0 {
		return 0
	}
	return float64(t.TP) / float64(t.TP+t.FP)
}

func (t tally) recall() float64 {
	if t.TP+t.FN == 0 {
		return 0
	}
	return float64(t.TP) / float64(t.TP+t.FN)
}

func (t tally) f1() float64 {
	p, r := t.precision(), t.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

type report struct {
	Documents      int                `json:"documents"`
	LabeledSpans   int                `json:"labeled_spans"`
	Strict         map[string]scores  `json:"strict"`
	Relaxed        map[string]scores  `json:"relaxed"`
	StrictOverall  scores             `json:"strict_overall"`
	RelaxedOverall scores             `json:"relaxed_overall"`
	Latency        latencyStats       `json:"latency"`
	GeneratedAt    string             `json:"generated_at"`
	FalsePositives []falsePositiveRow `json:"sample_false_positives"`
}

type scores struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

type latencyStats struct {
	Docs          int     `json:"docs"`
	Iterations    int     `json:"iterations"`
	MeanMicros    float64 `json:"mean_micros"`
	P50Micros     float64 `json:"p50_micros"`
	P95Micros     float64 `json:"p95_micros"`
	P99Micros     float64 `json:"p99_micros"`
	MaxMicros     float64 `json:"max_micros"`
	DocsPerSecond float64 `json:"docs_per_second"`
}

type falsePositiveRow struct {
	DocID string `json:"doc_id"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func toScores(t tally) scores {
	return scores{TP: t.TP, FP: t.FP, FN: t.FN, Precision: t.precision(), Recall: t.recall(), F1: t.f1()}
}

func main() {
	corpusPath := flag.String("corpus", "testdata/corpus.jsonl", "path to the labeled corpus")
	jsonOut := flag.String("json", "", "optional path to write the report as JSON")
	iterations := flag.Int("iterations", 20, "latency measurement passes over the corpus")
	flag.Parse()

	docs, err := loadCorpus(*corpusPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load corpus: %v\n", err)
		os.Exit(1)
	}

	engine := detect.NewEngine()
	strict := map[string]*tally{}
	relaxed := map[string]*tally{}
	var fpSamples []falsePositiveRow
	labeled := 0

	for _, doc := range docs {
		labeled += len(doc.Entities)
		found := engine.Find(doc.Text)

		scoreDoc(doc, found, strict, true, &fpSamples)
		scoreDoc(doc, found, relaxed, false, nil)
	}

	lat := measureLatency(engine, docs, *iterations)

	rep := report{
		Documents:      len(docs),
		LabeledSpans:   labeled,
		Strict:         finalize(strict),
		Relaxed:        finalize(relaxed),
		StrictOverall:  toScores(sum(strict)),
		RelaxedOverall: toScores(sum(relaxed)),
		Latency:        lat,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		FalsePositives: sampleN(fpSamples, 10),
	}

	printReport(rep)

	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write json: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nreport written to %s\n", *jsonOut)
	}
}

// scoreDoc compares detections against labels for one document.
//
// Each label may be claimed by at most one detection and vice versa, so that a
// detector emitting the same span twice cannot inflate its own recall.
func scoreDoc(doc document, found []detect.Match, acc map[string]*tally, exact bool, fps *[]falsePositiveRow) {
	usedLabel := make([]bool, len(doc.Entities))
	usedFound := make([]bool, len(found))

	for fi, f := range found {
		for li, l := range doc.Entities {
			if usedLabel[li] || string(f.Type) != l.Type {
				continue
			}
			hit := f.Start == l.Start && f.End == l.End
			if !exact {
				hit = f.Start < l.End && l.Start < f.End
			}
			if hit {
				usedLabel[li], usedFound[fi] = true, true
				bump(acc, l.Type).TP++
				break
			}
		}
	}
	for fi, f := range found {
		if !usedFound[fi] {
			bump(acc, string(f.Type)).FP++
			if fps != nil {
				*fps = append(*fps, falsePositiveRow{DocID: doc.ID, Type: string(f.Type), Value: f.Value})
			}
		}
	}
	for li, l := range doc.Entities {
		if !usedLabel[li] {
			bump(acc, l.Type).FN++
		}
	}
}

func bump(m map[string]*tally, k string) *tally {
	if m[k] == nil {
		m[k] = &tally{}
	}
	return m[k]
}

func finalize(m map[string]*tally) map[string]scores {
	out := make(map[string]scores, len(m))
	for k, v := range m {
		out[k] = toScores(*v)
	}
	return out
}

func sum(m map[string]*tally) tally {
	var t tally
	for _, v := range m {
		t.TP += v.TP
		t.FP += v.FP
		t.FN += v.FN
	}
	return t
}

// measureLatency times detection only, excluding corpus I/O, so the number
// reported is the overhead the proxy actually adds to a request.
func measureLatency(engine *detect.Engine, docs []document, iterations int) latencyStats {
	var samples []float64
	for i := 0; i < iterations; i++ {
		for _, doc := range docs {
			start := time.Now()
			engine.Find(doc.Text)
			samples = append(samples, float64(time.Since(start).Microseconds()))
		}
	}
	sort.Float64s(samples)

	var total float64
	for _, s := range samples {
		total += s
	}
	mean := total / float64(len(samples))

	pick := func(p float64) float64 {
		idx := int(p * float64(len(samples)-1))
		return samples[idx]
	}
	return latencyStats{
		Docs:          len(docs),
		Iterations:    iterations,
		MeanMicros:    mean,
		P50Micros:     pick(0.50),
		P95Micros:     pick(0.95),
		P99Micros:     pick(0.99),
		MaxMicros:     samples[len(samples)-1],
		DocsPerSecond: 1_000_000 / mean,
	}
}

func sampleN(rows []falsePositiveRow, n int) []falsePositiveRow {
	if len(rows) <= n {
		return rows
	}
	return rows[:n]
}

func loadCorpus(path string) ([]document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var docs []document
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var d document
		if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, sc.Err()
}

func printReport(r report) {
	fmt.Printf("PIIShield detection benchmark\n")
	fmt.Printf("%d documents, %d labeled spans\n\n", r.Documents, r.LabeledSpans)

	types := make([]string, 0, len(r.Strict))
	for k := range r.Strict {
		types = append(types, k)
	}
	sort.Strings(types)

	fmt.Printf("%-14s %5s %5s %5s  %9s %7s %7s   %8s\n", "ENTITY", "TP", "FP", "FN", "PRECISION", "RECALL", "F1", "RELAXED_R")
	fmt.Println("---------------------------------------------------------------------------------")
	for _, t := range types {
		s := r.Strict[t]
		rel := r.Relaxed[t]
		fmt.Printf("%-14s %5d %5d %5d  %9.3f %7.3f %7.3f   %8.3f\n",
			t, s.TP, s.FP, s.FN, s.Precision, s.Recall, s.F1, rel.Recall)
	}
	fmt.Println("---------------------------------------------------------------------------------")
	fmt.Printf("%-14s %5d %5d %5d  %9.3f %7.3f %7.3f   %8.3f\n",
		"OVERALL", r.StrictOverall.TP, r.StrictOverall.FP, r.StrictOverall.FN,
		r.StrictOverall.Precision, r.StrictOverall.Recall, r.StrictOverall.F1, r.RelaxedOverall.Recall)

	fmt.Printf("\nRedaction latency (detection only, %d passes over %d docs)\n", r.Latency.Iterations, r.Latency.Docs)
	fmt.Printf("  mean %.1fus   p50 %.1fus   p95 %.1fus   p99 %.1fus   max %.1fus\n",
		r.Latency.MeanMicros, r.Latency.P50Micros, r.Latency.P95Micros, r.Latency.P99Micros, r.Latency.MaxMicros)
	fmt.Printf("  throughput %.0f documents/sec/core\n", r.Latency.DocsPerSecond)

	if len(r.FalsePositives) > 0 {
		fmt.Printf("\nSample false positives (first %d)\n", len(r.FalsePositives))
		for _, fp := range r.FalsePositives {
			fmt.Printf("  %-10s %-12s %q\n", fp.DocID, fp.Type, fp.Value)
		}
	}
}
