// retime turns the audit log a kind cluster wrote while hack/send replayed a
// genmonth plan into the example history: each request gets the time the
// plan gave it, spread over a month, instead of the few minutes the
// recording took. Writes the cluster's controllers made in response keep
// their offset from the request before them. Events from before the first
// planned request (the cluster booting) are dropped.
//
//	go run ./hack/retime -plan plan.ndjson -in raw-audit.log -out examples/audit.log
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

func main() {
	planPath := flag.String("plan", "", "genmonth plan")
	in := flag.String("in", "", "audit log written by the recording cluster")
	out := flag.String("out", "", "retimed log")
	flag.Parse()

	planned := map[string]time.Time{}
	for _, ev := range readEvents(*planPath) {
		planned[string(ev.AuditID)] = ev.RequestReceivedTimestamp.Time
	}
	events := readEvents(*in)

	// Anchors map recording time to plan time: each planned request is
	// one; anything in between keeps its offset from the anchor before it.
	type anchor struct{ real, plan time.Time }
	var anchors []anchor
	for _, ev := range events {
		if at, ok := planned[string(ev.AuditID)]; ok {
			anchors = append(anchors, anchor{ev.RequestReceivedTimestamp.Time, at})
		}
	}
	if len(anchors) == 0 {
		fail(fmt.Errorf("no event in %s is in the plan", *in))
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].real.Before(anchors[j].real) })
	first := anchors[0].real.Add(-time.Second)
	mapTime := func(t time.Time) (time.Time, bool) {
		if t.Before(first) {
			return t, false
		}
		i := sort.Search(len(anchors), func(i int) bool { return anchors[i].real.After(t) }) - 1
		if i < 0 {
			i = 0
		}
		return anchors[i].plan.Add(t.Sub(anchors[i].real)), true
	}

	// Object timestamps have one-second resolution. hack/send paces requests
	// at least a second apart, so a second holds at most one planned
	// request: a timestamp in it belongs to that request.
	mapSecond := func(t time.Time) (time.Time, bool) {
		i := sort.Search(len(anchors), func(i int) bool { return !anchors[i].real.Before(t) })
		if i < len(anchors) && anchors[i].real.Before(t.Add(time.Second)) {
			return anchors[i].plan.Truncate(time.Second), true
		}
		return mapTime(t)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	kept, dropped := 0, 0
	for _, ev := range events {
		at, ok := mapTime(ev.RequestReceivedTimestamp.Time)
		if !ok {
			dropped++
			continue
		}
		if p, ok := planned[string(ev.AuditID)]; ok {
			at = p
		}
		shift := at.Sub(ev.RequestReceivedTimestamp.Time)
		ev.RequestReceivedTimestamp = metav1.NewMicroTime(at)
		ev.StageTimestamp = metav1.NewMicroTime(ev.StageTimestamp.Add(shift))
		// Timestamps inside the objects (creationTimestamp, managedFields
		// times) move the same way.
		for _, raw := range []*runtime.Unknown{ev.RequestObject, ev.ResponseObject} {
			if raw == nil {
				continue
			}
			var v any
			if err := json.Unmarshal(raw.Raw, &v); err != nil {
				fail(err)
			}
			v = walk(v, mapSecond)
			b, err := json.Marshal(v)
			if err != nil {
				fail(err)
			}
			raw.Raw = b
		}
		if err := enc.Encode(ev); err != nil {
			fail(err)
		}
		kept++
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "kept %d events, dropped %d from before the plan\n", kept, dropped)
}

// walk rewrites every RFC 3339 timestamp from the recording.
func walk(v any, mapTime func(time.Time) (time.Time, bool)) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = walk(e, mapTime)
		}
	case []any:
		for i, e := range x {
			x[i] = walk(e, mapTime)
		}
	case string:
		if t, err := time.Parse(time.RFC3339, x); err == nil {
			if m, ok := mapTime(t); ok {
				return m.UTC().Format(time.RFC3339)
			}
		}
	}
	return v
}

func readEvents(path string) []auditv1.Event {
	f, err := os.Open(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	var evs []auditv1.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var ev auditv1.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			fail(err)
		}
		evs = append(evs, ev)
	}
	if err := sc.Err(); err != nil {
		fail(err)
	}
	return evs
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
