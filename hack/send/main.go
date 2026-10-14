// send replays the writes in an audit log (or a genmonth plan) against a
// real API server, in order, as the users who made them. Each request
// carries its original audit ID in the Audit-ID header, so the server's own
// audit log can be joined back to the input.
//
// Writes by system: users (controllers, the scheduler, kubelets) are not
// sent: the cluster's own controllers make their own. Patches are not sent,
// because an audit log does not record the patch type.
//
//	go run ./hack/send -kubeconfig kind.kubeconfig -log plan.ndjson
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/ahmed-hashim-pro/admission-replay/history"
)

func main() {
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig of the cluster to send to")
	logPath := flag.String("log", "", "audit log or plan to replay")
	results := flag.String("results", "", "write one line per request: <audit ID> <HTTP code> <message>")
	pace := flag.Duration("pace", 0, "start requests at least this far apart")
	flag.Parse()
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)
	if *logPath == "" {
		fmt.Fprintln(os.Stderr, "usage: send -kubeconfig FILE -log FILE [-results FILE]")
		os.Exit(2)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	check(err)
	cfg.QPS, cfg.Burst = 200, 400
	cfg.WarningHandler = rest.NoWarnings{}
	log, err := history.ReadFile(*logPath)
	check(err)

	var out *os.File
	if *results != "" {
		out, err = os.Create(*results)
		check(err)
		defer out.Close()
	}
	ctx := context.Background()
	sent, skipped, failed := 0, 0, 0
	var last time.Time
	for _, e := range log.Entries {
		if strings.HasPrefix(e.User.GetName(), "system:") || e.Verb == "patch" {
			skipped++
			continue
		}
		if wait := time.Until(last.Add(*pace)); wait > 0 {
			time.Sleep(wait)
		}
		last = time.Now()
		client, err := clientFor(cfg, e)
		check(err)
		ns := e.Namespace
		if e.Resource.Group == "" && e.Resource.Resource == "namespaces" {
			ns = "" // audit logs put a namespace's own name here for some verbs
		}
		ri := client.Resource(e.Resource).Namespace(ns)
		// Retry what a loaded API server or etcd throws back (timeouts,
		// 429s, 5xx). A write that timed out may still have landed, so a
		// retried create that finds its object, or a retried delete that
		// finds it gone, counts as done.
		var serr error
		retried := false
		serr = retry.OnError(retry.DefaultBackoff, transient, func() error {
			err := write(ctx, ri, e)
			if err != nil && transient(err) {
				retried = true
			}
			if retried && ((e.Verb == "create" && apierrors.IsAlreadyExists(err)) || (e.Verb == "delete" && apierrors.IsNotFound(err))) {
				return nil
			}
			return err
		})
		sent++
		code, msg := 200, ""
		if serr != nil {
			failed++
			code, msg = 500, serr.Error()
			if se, ok := serr.(apierrors.APIStatus); ok {
				code = int(se.Status().Code)
			}
		}
		if out != nil {
			fmt.Fprintf(out, "%s %d %s\n", e.ID, code, msg)
		}
	}
	fmt.Fprintf(os.Stderr, "sent %d writes (%d rejected), skipped %d\n", sent, failed, skipped)
}

func write(ctx context.Context, ri dynamic.ResourceInterface, e *history.Entry) error {
	switch e.Verb {
	case "create":
		_, err := ri.Create(ctx, clean(e.Request), metav1.CreateOptions{FieldManager: "send"})
		return err
	case "update":
		// Controllers write status between our read and our update; on a
		// conflict, read again and resend the same body.
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cur, err := ri.Get(ctx, e.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			body := clean(e.Request)
			body.SetResourceVersion(cur.GetResourceVersion())
			_, err = ri.Update(ctx, body, metav1.UpdateOptions{FieldManager: "send"})
			return err
		})
	case "delete":
		return ri.Delete(ctx, e.Name, metav1.DeleteOptions{})
	}
	return fmt.Errorf("verb %s is not sent", e.Verb)
}

func transient(err error) bool {
	return apierrors.IsServerTimeout(err) || apierrors.IsTimeout(err) || apierrors.IsTooManyRequests(err) ||
		apierrors.IsInternalError(err) || apierrors.IsServiceUnavailable(err) ||
		strings.Contains(err.Error(), "request timed out")
}

// clientFor impersonates the entry's user and stamps its audit ID. The
// transport is per request, so it is built per entry; the dynamic client is
// cheap.
func clientFor(base *rest.Config, e *history.Entry) (*dynamic.DynamicClient, error) {
	cfg := rest.CopyConfig(base)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: e.User.GetName(), Groups: e.User.GetGroups()}
	id := e.ID
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		return roundTripper(func(r *http.Request) (*http.Response, error) {
			r = r.Clone(r.Context())
			r.Header.Set("Audit-ID", id)
			return rt.RoundTrip(r)
		})
	}
	return dynamic.NewForConfig(cfg)
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// clean drops what the server sets, in case the input is a recorded log
// whose request bodies came from a client that sent them back.
func clean(u *unstructured.Unstructured) *unstructured.Unstructured {
	u = u.DeepCopy()
	for _, f := range []string{"uid", "resourceVersion", "creationTimestamp", "generation", "managedFields"} {
		unstructured.RemoveNestedField(u.Object, "metadata", f)
	}
	unstructured.RemoveNestedField(u.Object, "status")
	return u
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
