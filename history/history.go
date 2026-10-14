// Package history reads Kubernetes audit logs (audit.k8s.io/v1 events) and
// turns them into the sequence of admission requests they record.
package history

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

// Entry is one write request from the log.
type Entry struct {
	ID          string
	Time        time.Time
	User        user.Info
	Verb        string // create, update, patch, delete
	Resource    schema.GroupVersionResource
	Subresource string
	Namespace   string
	Name        string
	Code        int32 // HTTP status of the original request
	Request     *unstructured.Unstructured
	Response    *unstructured.Unstructured
	Line        int
}

// Failed reports whether the original request was rejected, so it changed
// nothing in the cluster.
func (e *Entry) Failed() bool { return e.Code >= 300 }

// Log is a parsed audit log.
type Log struct {
	Entries []*Entry
	// Skipped counts events that are not replayable writes, by reason.
	Skipped map[string]int
}

var writeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true}

// ReadFile reads an audit log: one JSON event per line (what the API
// server's log backend writes), or a JSON EventList; gzip-compressed or not.
func ReadFile(path string) (*Log, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

func Read(r io.Reader) (*Log, error) {
	br := bufio.NewReader(r)
	if head, _ := br.Peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		br = bufio.NewReader(gz)
	}
	data, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	var events []auditv1.Event
	var lines []int
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' && bytes.Contains(trimmed[:min(len(trimmed), 200)], []byte(`"EventList"`)) {
		var list auditv1.EventList
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("EventList: %w", err)
		}
		events = list.Items
		for i := range events {
			lines = append(lines, i+1)
		}
	} else {
		for n, line := range bytes.Split(data, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var ev auditv1.Event
			if err := json.Unmarshal(line, &ev); err != nil {
				return nil, fmt.Errorf("line %d: not an audit event: %w", n+1, err)
			}
			if ev.Kind != "" && ev.Kind != "Event" {
				return nil, fmt.Errorf("line %d: kind %q, want an audit.k8s.io Event", n+1, ev.Kind)
			}
			events = append(events, ev)
			lines = append(lines, n+1)
		}
	}
	log := &Log{Skipped: map[string]int{}}
	for i := range events {
		ev := &events[i]
		e, reason := entry(ev)
		if e == nil {
			if reason != "" {
				log.Skipped[reason]++
			}
			continue
		}
		e.Line = lines[i]
		log.Entries = append(log.Entries, e)
	}
	// The log backend writes events as requests complete, so concurrent
	// requests can appear out of order. Replay in the order they arrived.
	sort.SliceStable(log.Entries, func(i, j int) bool { return log.Entries[i].Time.Before(log.Entries[j].Time) })
	return log, nil
}

func entry(ev *auditv1.Event) (*Entry, string) {
	if ev.Stage != auditv1.StageResponseComplete {
		return nil, "" // RequestReceived/ResponseStarted duplicate the same request
	}
	if !writeVerbs[ev.Verb] {
		return nil, ""
	}
	if ev.ObjectRef == nil || ev.ObjectRef.Resource == "" {
		return nil, "no objectRef"
	}
	if ev.ObjectRef.Subresource != "" {
		return nil, "subresource"
	}
	e := &Entry{
		ID:          string(ev.AuditID),
		Time:        ev.RequestReceivedTimestamp.Time,
		Verb:        ev.Verb,
		Resource:    schema.GroupVersionResource{Group: ev.ObjectRef.APIGroup, Version: ev.ObjectRef.APIVersion, Resource: ev.ObjectRef.Resource},
		Subresource: ev.ObjectRef.Subresource,
		Namespace:   ev.ObjectRef.Namespace,
		Name:        ev.ObjectRef.Name,
		Code:        200,
	}
	u := ev.User
	if ev.ImpersonatedUser != nil {
		u = *ev.ImpersonatedUser
	}
	extra := map[string][]string{}
	for k, v := range u.Extra {
		extra[k] = []string(v)
	}
	e.User = &user.DefaultInfo{Name: u.Username, UID: u.UID, Groups: u.Groups, Extra: extra}
	if ev.ResponseStatus != nil && ev.ResponseStatus.Code != 0 {
		e.Code = ev.ResponseStatus.Code
	}
	var err error
	if e.Request, err = object(ev.RequestObject); err != nil {
		return nil, "unreadable requestObject"
	}
	if e.Response, err = object(ev.ResponseObject); err != nil {
		return nil, "unreadable responseObject"
	}
	if e.Verb != "delete" && e.Request == nil && e.Response == nil {
		return nil, "no request or response body (audit level below Request)"
	}
	return e, ""
}

func object(raw *runtime.Unknown) (*unstructured.Unstructured, error) {
	if raw == nil || len(raw.Raw) == 0 {
		return nil, nil
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(raw.Raw); err != nil {
		return nil, err
	}
	return u, nil
}

// IsObject reports whether u is a resource rather than a Status or options
// object (a delete's request body is DeleteOptions; a failed request's
// response is a Status).
func IsObject(u *unstructured.Unstructured) bool {
	if u == nil {
		return false
	}
	switch u.GetKind() {
	case "", "Status", "DeleteOptions":
		return false
	}
	return !strings.HasSuffix(u.GetKind(), "Options")
}
