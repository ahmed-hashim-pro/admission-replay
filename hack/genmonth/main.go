// genmonth writes the requests behind the example history: a month of
// writes by a small company's engineers and CI to a cluster, three of which
// should never have been admitted. The output is a plan in audit-event form
// (requestObject, user, intended time); hack/record.sh sends it to a real API
// server and keeps the audit log that server writes, which is the example.
//
//	go run ./hack/genmonth -out plan.ndjson -bad examples/bad.txt
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

type obj = map[string]any

type req struct {
	at    time.Time
	who   string
	verb  string
	group string
	ver   string
	res   string
	ns    string
	name  string
	body  obj
	bad   string
}

var groups = map[string][]string{
	"ci-deploy": {"ci"},
	"alice":     {"shop-devs"},
	"bob":       {"shop-devs"},
	"carol":     {"data-eng"},
	"dana":      {"platform"},
}

var start = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func main() {
	out := flag.String("out", "plan.ndjson", "plan file to write")
	badOut := flag.String("bad", "examples/bad.txt", "labels file to write")
	flag.Parse()

	rng := rand.New(rand.NewPCG(2026, 9))
	var reqs []req
	add := func(r req) { reqs = append(reqs, r) }
	day := func(d int, h, m int) time.Time {
		return start.Add(time.Duration(d)*24*time.Hour + time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
	}

	// Day 0: the platform team sets the cluster up.
	nsLabels := []struct {
		name   string
		labels map[string]string
	}{
		{"shop-prod", map[string]string{"env": "prod", "team": "shop"}},
		{"shop-staging", map[string]string{"env": "staging", "team": "shop"}},
		{"data-prod", map[string]string{"env": "prod", "team": "data"}},
		{"platform", map[string]string{"env": "prod", "team": "platform"}},
		{"monitoring", map[string]string{"env": "prod", "team": "platform"}},
	}
	for i, n := range nsLabels {
		add(req{at: day(0, 9, i), who: "dana", verb: "create", ver: "v1", res: "namespaces", name: n.name,
			body: obj{"apiVersion": "v1", "kind": "Namespace", "metadata": obj{"name": n.name, "labels": n.labels}}})
	}

	// The shop: five services in staging and prod.
	type svc struct {
		name     string
		version  [3]int
		replicas int
		port     int
		noMemLim map[string]bool // namespaces where the legacy manifest has no memory limit
	}
	shop := []*svc{
		{name: "web", version: [3]int{3, 12, 0}, replicas: 3, port: 8080},
		{name: "cart", version: [3]int{2, 4, 1}, replicas: 2, port: 8080},
		{name: "checkout", version: [3]int{1, 9, 3}, replicas: 2, port: 8080},
		{name: "payments", version: [3]int{1, 4, 2}, replicas: 2, port: 8443},
		{name: "search", version: [3]int{0, 21, 0}, replicas: 1, port: 9200, noMemLim: map[string]bool{"shop-staging": true}},
	}
	image := func(s *svc) string {
		return fmt.Sprintf("registry.example.com/shop/%s:%d.%d.%d", s.name, s.version[0], s.version[1], s.version[2])
	}
	shopDeploy := func(s *svc, ns string, extra func(spec obj)) obj {
		limits := obj{"cpu": "500m", "memory": "512Mi"}
		if s.noMemLim[ns] {
			limits = obj{"cpu": "500m"}
		}
		replicas := s.replicas
		if ns == "shop-staging" {
			replicas = 1
		}
		pod := obj{
			"securityContext": obj{"runAsNonRoot": true, "runAsUser": 10001},
			"containers": []any{obj{
				"name": s.name, "image": image(s),
				"ports":           []any{obj{"containerPort": s.port}},
				"resources":       obj{"requests": obj{"cpu": "100m", "memory": "128Mi"}, "limits": limits},
				"securityContext": obj{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true},
			}},
		}
		if extra != nil {
			extra(pod)
		}
		return deployment(ns, s.name, "shop", replicas, pod)
	}
	for i, s := range shop {
		for j, ns := range []string{"shop-staging", "shop-prod"} {
			t := day(0, 10+j, i*3)
			add(req{at: t, who: "ci-deploy", verb: "create", group: "apps", ver: "v1", res: "deployments", ns: ns, name: s.name, body: shopDeploy(s, ns, nil)})
			add(req{at: t.Add(20 * time.Second), who: "ci-deploy", verb: "create", ver: "v1", res: "services", ns: ns, name: s.name, body: service(ns, s.name, s.port)})
			add(req{at: t.Add(40 * time.Second), who: "ci-deploy", verb: "create", ver: "v1", res: "configmaps", ns: ns, name: s.name + "-config", body: configMap(ns, s.name+"-config", map[string]string{"LOG_LEVEL": "info", "FEATURE_FLAGS": ""})})
		}
	}

	// Data: a nightly ETL CronJob, a loader Deployment with no limits (it
	// sizes its own heap), and Postgres.
	loader := func(v int) obj {
		return deployment("data-prod", "warehouse-loader", "data", 1, obj{
			"containers": []any{obj{
				"name": "loader", "image": fmt.Sprintf("registry.example.com/data/warehouse-loader:2.%d.0", v),
				"env":             []any{obj{"name": "HEAP_FRACTION", "value": "0.7"}},
				"securityContext": obj{"runAsNonRoot": true, "runAsUser": 20001},
			}},
		})
	}
	etl := func(v int, schedule string) obj {
		return obj{
			"apiVersion": "batch/v1", "kind": "CronJob",
			"metadata": obj{"name": "etl-nightly", "namespace": "data-prod", "labels": obj{"team": "data", "app": "etl-nightly"}},
			"spec": obj{
				"schedule": schedule, "concurrencyPolicy": "Forbid", "suspend": true,
				"jobTemplate": obj{"spec": obj{"template": obj{"spec": obj{
					"restartPolicy":   "OnFailure",
					"securityContext": obj{"runAsNonRoot": true, "runAsUser": 20001},
					"containers": []any{obj{
						"name": "etl", "image": fmt.Sprintf("registry.example.com/data/etl:5.%d.0", v),
						"resources": obj{"limits": obj{"cpu": "2", "memory": "4Gi"}},
					}},
				}}}},
			},
		}
	}
	postgres := func(minor int) obj {
		return obj{
			"apiVersion": "apps/v1", "kind": "StatefulSet",
			"metadata": obj{"name": "postgres", "namespace": "data-prod", "labels": obj{"team": "data", "app": "postgres"}},
			"spec": obj{
				"serviceName": "postgres", "replicas": 1,
				"selector": obj{"matchLabels": obj{"app": "postgres"}},
				"template": obj{
					"metadata": obj{"labels": obj{"app": "postgres", "team": "data"}},
					"spec": obj{
						"securityContext": obj{"runAsNonRoot": true, "runAsUser": 999, "fsGroup": 999},
						"containers": []any{obj{
							"name": "postgres", "image": fmt.Sprintf("registry.example.com/mirror/postgres:16.%d", minor),
							"resources": obj{"limits": obj{"cpu": "2", "memory": "8Gi"}},
						}},
					},
				},
			},
		}
	}
	add(req{at: day(1, 11, 0), who: "carol", verb: "create", group: "apps", ver: "v1", res: "statefulsets", ns: "data-prod", name: "postgres", body: postgres(3)})
	add(req{at: day(1, 11, 30), who: "carol", verb: "create", group: "apps", ver: "v1", res: "deployments", ns: "data-prod", name: "warehouse-loader", body: loader(7)})
	add(req{at: day(1, 11, 45), who: "carol", verb: "create", group: "batch", ver: "v1", res: "cronjobs", ns: "data-prod", name: "etl-nightly", body: etl(1, "0 2 * * *")})

	// Platform: an ingress proxy from upstream that binds :80 and :443 as
	// root, a cert renewer, and two node agents in monitoring.
	proxy := func(v string) obj {
		return deployment("platform", "ingress-proxy", "platform", 2, obj{
			"containers": []any{obj{
				"name": "controller", "image": "registry.k8s.io/ingress-nginx/controller:" + v,
				"ports":           []any{obj{"containerPort": 80}, obj{"containerPort": 443}},
				"resources":       obj{"limits": obj{"cpu": "1", "memory": "1Gi"}},
				"securityContext": obj{"allowPrivilegeEscalation": true, "capabilities": obj{"add": []any{"NET_BIND_SERVICE"}, "drop": []any{"ALL"}}},
			}},
		})
	}
	certs := func(v string) obj {
		return deployment("platform", "cert-renewer", "platform", 1, obj{
			"securityContext": obj{"runAsNonRoot": true, "runAsUser": 1000},
			"containers": []any{obj{
				"name": "renewer", "image": "quay.io/jetstack/cert-manager-controller:" + v,
				"resources": obj{"limits": obj{"cpu": "200m", "memory": "256Mi"}},
			}},
		})
	}
	nodeExporter := func(v string) obj {
		return daemonSet("monitoring", "node-exporter", obj{
			"hostPID": true, "hostNetwork": true,
			"securityContext": obj{"runAsNonRoot": true, "runAsUser": 65534},
			"containers": []any{obj{
				"name": "node-exporter", "image": "quay.io/prometheus/node-exporter:" + v,
				"args":         []any{"--path.procfs=/host/proc", "--path.sysfs=/host/sys"},
				"resources":    obj{"limits": obj{"cpu": "250m", "memory": "180Mi"}},
				"volumeMounts": []any{obj{"name": "proc", "mountPath": "/host/proc", "readOnly": true}, obj{"name": "sys", "mountPath": "/host/sys", "readOnly": true}},
			}},
			"volumes": []any{obj{"name": "proc", "hostPath": obj{"path": "/proc"}}, obj{"name": "sys", "hostPath": obj{"path": "/sys"}}},
		})
	}
	logShipper := func(v string, debug bool) obj {
		c := obj{
			"name": "shipper", "image": "registry.example.com/platform/log-shipper:" + v,
			"resources":    obj{"limits": obj{"cpu": "200m", "memory": "256Mi"}},
			"volumeMounts": []any{obj{"name": "varlog", "mountPath": "/var/log", "readOnly": true}},
		}
		vols := []any{obj{"name": "varlog", "hostPath": obj{"path": "/var/log"}}}
		if debug {
			c["securityContext"] = obj{"privileged": true}
			c["volumeMounts"] = append(c["volumeMounts"].([]any), obj{"name": "host", "mountPath": "/host"})
			vols = append(vols, obj{"name": "host", "hostPath": obj{"path": "/"}})
		}
		return daemonSet("monitoring", "log-shipper", obj{
			"securityContext": obj{"runAsUser": 0},
			"containers":      []any{c},
			"volumes":         vols,
		})
	}
	add(req{at: day(0, 15, 0), who: "dana", verb: "create", group: "apps", ver: "v1", res: "deployments", ns: "platform", name: "ingress-proxy", body: proxy("v1.11.2")})
	add(req{at: day(0, 15, 10), who: "dana", verb: "create", group: "apps", ver: "v1", res: "deployments", ns: "platform", name: "cert-renewer", body: certs("v1.15.3")})
	add(req{at: day(0, 15, 20), who: "dana", verb: "create", group: "apps", ver: "v1", res: "daemonsets", ns: "monitoring", name: "node-exporter", body: nodeExporter("v1.8.2")})
	add(req{at: day(0, 15, 30), who: "dana", verb: "create", group: "apps", ver: "v1", res: "daemonsets", ns: "monitoring", name: "log-shipper", body: logShipper("3.2.0", false)})

	// The month. Weekdays: CI ships to staging most days and to prod a
	// couple of times a week; people change config and scale.
	bump := func(s *svc) {
		if rng.IntN(6) == 0 {
			s.version[1]++
			s.version[2] = 0
		} else {
			s.version[2]++
		}
	}
	prodVersion := map[string][3]int{}
	for _, s := range shop {
		prodVersion[s.name] = s.version
	}
	loaderV, etlV := 7, 1
	for d := 1; d < 30; d++ {
		wd := start.AddDate(0, 0, d).Weekday()
		if wd == time.Saturday || wd == time.Sunday {
			continue
		}
		for _, s := range shop {
			if rng.Float64() < 0.7 {
				bump(s)
				add(req{at: day(d, 10, rng.IntN(240)), who: "ci-deploy", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-staging", name: s.name, body: shopDeploy(s, "shop-staging", nil)})
			}
			if (wd == time.Tuesday || wd == time.Thursday) && prodVersion[s.name] != s.version {
				prodVersion[s.name] = s.version
				add(req{at: day(d, 15, rng.IntN(90)), who: "ci-deploy", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-prod", name: s.name, body: shopDeploy(s, "shop-prod", nil)})
			}
		}
		// Config tweaks by the shop developers.
		if rng.Float64() < 0.6 {
			s := shop[rng.IntN(len(shop))]
			ns := []string{"shop-staging", "shop-prod"}[rng.IntN(2)]
			who := []string{"alice", "bob"}[rng.IntN(2)]
			flags := []string{"", "new-checkout", "new-checkout,fast-search", "fast-search"}[rng.IntN(4)]
			level := []string{"info", "debug", "info", "warn"}[rng.IntN(4)]
			add(req{at: day(d, 11+rng.IntN(6), rng.IntN(60)), who: who, verb: "update", ver: "v1", res: "configmaps", ns: ns, name: s.name + "-config",
				body: configMap(ns, s.name+"-config", map[string]string{"LOG_LEVEL": level, "FEATURE_FLAGS": flags})})
		}
		// Data team: loader releases and the ETL schedule.
		if rng.Float64() < 0.2 {
			loaderV++
			add(req{at: day(d, 13, rng.IntN(60)), who: "carol", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "data-prod", name: "warehouse-loader", body: loader(loaderV)})
		}
		if rng.Float64() < 0.12 {
			etlV++
			add(req{at: day(d, 14, rng.IntN(60)), who: "carol", verb: "update", group: "batch", ver: "v1", res: "cronjobs", ns: "data-prod", name: "etl-nightly", body: etl(etlV, []string{"0 2 * * *", "30 1 * * *"}[rng.IntN(2)])})
		}
	}

	// Scale-ups for the sale on the 18th, back down on the 22nd.
	for i, s := range shop[:3] {
		up := *s
		up.replicas = s.replicas * 2
		up.version = prodVersion[s.name]
		add(req{at: day(17, 16, i*5), who: "bob", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-prod", name: s.name, body: shopDeploy(&up, "shop-prod", nil)})
		down := up
		down.replicas = s.replicas
		add(req{at: day(21, 10, i*5), who: "bob", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-prod", name: s.name, body: shopDeploy(&down, "shop-prod", nil)})
	}
	// Platform upgrades.
	add(req{at: day(8, 14, 0), who: "dana", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "platform", name: "ingress-proxy", body: proxy("v1.11.3")})
	add(req{at: day(15, 14, 0), who: "dana", verb: "update", group: "apps", ver: "v1", res: "daemonsets", ns: "monitoring", name: "node-exporter", body: nodeExporter("v1.8.3")})
	add(req{at: day(16, 10, 0), who: "dana", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "platform", name: "cert-renewer", body: certs("v1.15.4")})
	add(req{at: day(23, 14, 0), who: "dana", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "platform", name: "ingress-proxy", body: proxy("v1.12.0")})
	add(req{at: day(24, 11, 0), who: "carol", verb: "update", group: "apps", ver: "v1", res: "statefulsets", ns: "data-prod", name: "postgres", body: postgres(4)})
	// A namespace for a short-lived experiment, created and torn down.
	add(req{at: day(9, 10, 0), who: "dana", verb: "create", ver: "v1", res: "namespaces", name: "search-experiment",
		body: obj{"apiVersion": "v1", "kind": "Namespace", "metadata": obj{"name": "search-experiment", "labels": obj{"env": "staging", "team": "shop"}}}})
	exp := *shop[4]
	exp.version = [3]int{0, 22, 0}
	add(req{at: day(9, 10, 30), who: "alice", verb: "create", group: "apps", ver: "v1", res: "deployments", ns: "search-experiment", name: "search", body: shopDeploy(&exp, "search-experiment", nil)})
	add(req{at: day(19, 17, 0), who: "alice", verb: "delete", group: "apps", ver: "v1", res: "deployments", ns: "search-experiment", name: "search"})
	add(req{at: day(19, 17, 5), who: "dana", verb: "delete", ver: "v1", res: "namespaces", name: "search-experiment"})

	// The three writes that should have been stopped.
	//
	// 1. A hotfix built on a laptop and pushed to a personal registry.
	hot := *shop[3]
	hot.version = prodVersion["payments"]
	hotfix := shopDeploy(&hot, "shop-prod", nil)
	podSpec(hotfix)["containers"].([]any)[0].(obj)["image"] = "docker.io/alice-dev/payments:hotfix-2"
	add(req{at: day(11, 22, 47), who: "alice", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-prod", name: "payments", body: hotfix,
		bad: "payments hotfix image from a personal Docker Hub account"})
	// Put it back the next morning.
	add(req{at: day(12, 9, 15), who: "alice", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-prod", name: "payments", body: shopDeploy(&hot, "shop-prod", nil)})
	// 2. Debugging a full disk: the log shipper gets the node's root
	//    filesystem, writable, in a privileged container.
	add(req{at: day(18, 3, 12), who: "bob", verb: "update", group: "apps", ver: "v1", res: "daemonsets", ns: "monitoring", name: "log-shipper", body: logShipper("3.2.0", true),
		bad: "log-shipper DaemonSet made privileged with the host's / mounted read-write"})
	add(req{at: day(18, 9, 40), who: "dana", verb: "update", group: "apps", ver: "v1", res: "daemonsets", ns: "monitoring", name: "log-shipper", body: logShipper("3.2.1", false)})
	// 3. A kernel tweak for connection limits, as a privileged init
	//    container on checkout in prod. It stays.
	co := *shop[2]
	co.version = prodVersion["checkout"]
	add(req{at: day(25, 16, 5), who: "bob", verb: "update", group: "apps", ver: "v1", res: "deployments", ns: "shop-prod", name: "checkout",
		body: shopDeploy(&co, "shop-prod", func(pod obj) {
			pod["initContainers"] = []any{obj{
				"name": "sysctl", "image": "registry.example.com/platform/busybox:1.36",
				"command":         []any{"sh", "-c", "sysctl -w net.core.somaxconn=4096"},
				"securityContext": obj{"privileged": true, "runAsNonRoot": false, "runAsUser": 0},
			}}
		}),
		bad: "checkout gets a privileged init container (sysctl tweak)"})

	sort.SliceStable(reqs, func(i, j int) bool { return reqs[i].at.Before(reqs[j].at) })

	f, err := os.Create(*out)
	check(err)
	enc := json.NewEncoder(f)
	var bad strings.Builder
	bad.WriteString("# Writes in examples/audit.log that should never have been admitted.\n# <audit ID>  <what it was>\n")
	for i, r := range reqs {
		id := fmt.Sprintf("%08x-0000-4000-8000-%012x", 0x5e9a0000+i, i)
		ev := auditv1.Event{
			TypeMeta: metav1.TypeMeta{APIVersion: "audit.k8s.io/v1", Kind: "Event"},
			Level:    auditv1.LevelRequestResponse, AuditID: types.UID(id),
			Stage: auditv1.StageResponseComplete, Verb: r.verb,
			User:                     authnv1.UserInfo{Username: "kubernetes-admin"},
			ImpersonatedUser:         &authnv1.UserInfo{Username: r.who, Groups: groups[r.who]},
			ObjectRef:                &auditv1.ObjectReference{APIGroup: r.group, APIVersion: r.ver, Resource: r.res, Namespace: r.ns, Name: r.name},
			RequestReceivedTimestamp: metav1.NewMicroTime(r.at),
			StageTimestamp:           metav1.NewMicroTime(r.at),
		}
		if r.body != nil {
			raw, err := json.Marshal(r.body)
			check(err)
			ev.RequestObject = &runtime.Unknown{Raw: raw, ContentType: runtime.ContentTypeJSON}
		}
		check(enc.Encode(ev))
		if r.bad != "" {
			fmt.Fprintf(&bad, "%s  %s\n", id, r.bad)
		}
	}
	check(f.Close())
	check(os.WriteFile(*badOut, []byte(bad.String()), 0o644))
	fmt.Fprintf(os.Stderr, "%d requests, %d labelled bad\n", len(reqs), strings.Count(bad.String(), "\n")-2)
}

func deployment(ns, name, team string, replicas int, pod obj) obj {
	return obj{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": obj{"name": name, "namespace": ns, "labels": obj{"app": name, "team": team}},
		"spec": obj{
			"replicas": replicas,
			"selector": obj{"matchLabels": obj{"app": name}},
			"template": obj{"metadata": obj{"labels": obj{"app": name, "team": team}}, "spec": pod},
		},
	}
}

func daemonSet(ns, name string, pod obj) obj {
	return obj{
		"apiVersion": "apps/v1", "kind": "DaemonSet",
		"metadata": obj{"name": name, "namespace": ns, "labels": obj{"app": name, "team": "platform"}},
		"spec": obj{
			"selector": obj{"matchLabels": obj{"app": name}},
			"template": obj{"metadata": obj{"labels": obj{"app": name, "team": "platform"}}, "spec": pod},
		},
	}
}

func service(ns, name string, port int) obj {
	return obj{
		"apiVersion": "v1", "kind": "Service",
		"metadata": obj{"name": name, "namespace": ns, "labels": obj{"app": name}},
		"spec":     obj{"selector": obj{"app": name}, "ports": []any{obj{"port": port, "targetPort": port}}},
	}
}

func configMap(ns, name string, data map[string]string) obj {
	return obj{"apiVersion": "v1", "kind": "ConfigMap", "metadata": obj{"name": name, "namespace": ns}, "data": data}
}

func podSpec(d obj) obj {
	return d["spec"].(obj)["template"].(obj)["spec"].(obj)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
