package history

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const create = `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"a1","stage":"ResponseComplete","verb":"create","user":{"username":"kubernetes-admin"},"impersonatedUser":{"username":"alice","groups":["devs"]},"objectRef":{"resource":"configmaps","namespace":"shop","name":"c","apiVersion":"v1"},"responseStatus":{"code":201},"requestObject":{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"c"}},"responseObject":{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"c","namespace":"shop","resourceVersion":"7"}},"requestReceivedTimestamp":"2026-09-02T10:00:00.000000Z","stageTimestamp":"2026-09-02T10:00:00.010000Z"}`

const earlier = `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"a0","stage":"ResponseComplete","verb":"delete","user":{"username":"bob"},"objectRef":{"resource":"configmaps","namespace":"shop","name":"old","apiVersion":"v1"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-09-01T10:00:00.000000Z","stageTimestamp":"2026-09-01T10:00:00.010000Z"}`

func TestRead(t *testing.T) {
	lines := []string{
		create,
		strings.Replace(create, `"stage":"ResponseComplete"`, `"stage":"RequestReceived"`, 1), // same request, earlier stage
		strings.Replace(create, `"verb":"create"`, `"verb":"get"`, 1),                         // a read
		strings.Replace(create, `"name":"c","apiVersion":"v1"}`, `"name":"c","apiVersion":"v1","subresource":"status"}`, 1),
		earlier,
	}
	log, err := Read(strings.NewReader(strings.Join(lines, "\n") + "\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Entries) != 2 {
		t.Fatalf("%d entries", len(log.Entries))
	}
	// Sorted by the time the request arrived, not by position in the file.
	if log.Entries[0].ID != "a0" || log.Entries[1].ID != "a1" {
		t.Fatalf("order: %s %s", log.Entries[0].ID, log.Entries[1].ID)
	}
	e := log.Entries[1]
	if e.User.GetName() != "alice" || e.User.GetGroups()[0] != "devs" {
		t.Fatalf("impersonated user not used: %+v", e.User)
	}
	if e.Code != 201 || e.Failed() || e.Response.GetResourceVersion() != "7" || e.Line != 1 {
		t.Fatalf("%+v", e)
	}
	if log.Skipped["subresource"] != 1 {
		t.Fatalf("skipped: %v", log.Skipped)
	}
}

func TestReadEventListAndGzip(t *testing.T) {
	list := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[` + create + `,` + earlier + `]}`
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(list))
	w.Close()
	for name, in := range map[string][]byte{"list": []byte(list), "gzip": gz.Bytes()} {
		log, err := Read(bytes.NewReader(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(log.Entries) != 2 {
			t.Fatalf("%s: %d entries", name, len(log.Entries))
		}
	}
}

func TestReadErrors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{create + "\nnot json\n", "line 2: not an audit event"},
		{`{"kind":"Pod","apiVersion":"v1"}`, `kind "Pod"`},
	} {
		if _, err := Read(strings.NewReader(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("got %v, want %q", err, tc.want)
		}
	}
}

func TestMetadataLevelIsSkipped(t *testing.T) {
	meta := strings.NewReplacer(`,"requestObject":{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"c"}}`, "",
		`,"responseObject":{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"c","namespace":"shop","resourceVersion":"7"}}`, "").Replace(create)
	log, err := Read(strings.NewReader(meta))
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Entries) != 0 || log.Skipped["no request or response body (audit level below Request)"] != 1 {
		t.Fatalf("%+v", log)
	}
}

func TestIsObject(t *testing.T) {
	log, _ := Read(strings.NewReader(create))
	if !IsObject(log.Entries[0].Response) || IsObject(nil) {
		t.Fatal("IsObject")
	}
}
