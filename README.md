# admission-replay

[![CI](https://github.com/ahmed-hashim-pro/admission-replay/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed-hashim-pro/admission-replay/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Replays a Kubernetes cluster's audit log through a proposed
ValidatingAdmissionPolicy before you turn it on. It reports which
legitimate writes the policy would have blocked and which of the changes you
know were bad it would have let through.

Turning on an admission policy is a bet on traffic you haven't looked at. A
rule that reads as strict can stop CI from deploying the service that never
set a memory limit. It can also never match the DaemonSet where the real
damage happened. The usual advice is to bind it with `[Warn, Audit]` first and
wait a few weeks, and that only tells you about the weeks to come. Your API
server's audit log already holds the past month of writes. `admission-replay`
sends every one of them through the policy, using the API server's own
admission code, and scores the result:

```
$ admission-replay compare examples/audit.log examples/policies/*.yaml --bad examples/bad.txt
examples/audit.log: 198 writes from 2026-09-01 to 2026-09-30 (29.2 days), 3 labelled bad

     policy              bad caught  legit blocked  by controllers  warned  skipped
  1  targeted                   3/3              0               0      21        0
  2  registry-allowlist         1/3              0               0       0        0
  3  strict-baseline            1/3             26               0       0        0

ranked by bad writes caught, then legitimate writes blocked, then warnings.

let through:
  registry-allowlist  log-shipper DaemonSet made privileged with the host's / mounted read-write
                      checkout gets a privileged init container (sysctl tweak)
  strict-baseline     log-shipper DaemonSet made privileged with the host's / mounted read-write
                      checkout gets a privileged init container (sysctl tweak)
```

The example is a month of writes by a small company's CI and four engineers.
They work across five namespaces with Deployments, DaemonSets, a StatefulSet
and a CronJob. Three of the writes should never have been admitted:

- a payments hotfix pulled from someone's personal Docker Hub account
- a log-shipper DaemonSet made privileged, with the node's `/` mounted
  read-write
- a privileged init container added to checkout in prod

`strict-baseline` is the policy that looks safest on paper: a trusted
registry, pinned tags, limits, non-root and no privileged containers. Over
the month it blocks 26 legitimate writes:

- CI's deploys of the one service without a memory limit
- every release of the data team's loader
- the platform team's upstream ingress controller

It catches only one of the three bad writes. It matches Deployments, so the
DaemonSet never reaches it. It checks `containers`, so the init container
doesn't either. `targeted` catches all three and blocks nothing. It denies
privilege and writable host mounts in every workload kind and every
container list, trusts only known registries, and only *warns* about
missing limits.

The month is invented, but the log is real. It was recorded by a real
kube-apiserver (on [kind](https://kind.sigs.k8s.io)) while the month's
requests were sent to it, and then moved onto a September calendar.

![Terminal recording: compare ranks targeted first, catching 3 of 3 bad writes and blocking nothing; strict-baseline blocks 26 legitimate writes and lets two bad ones through. Replaying strict-baseline lists the two it let through, a privileged DaemonSet and a privileged init container, with "admitted: no validation failed". Replaying targeted with --fail-on-block --fail-on-miss lists all three bad writes caught, each with the validation that caught it, and exits 0](docs/demo.gif)

## Is the replay faithful?

The evaluation isn't a reimplementation. `admission-replay` runs the
ValidatingAdmissionPolicy admission plugin from `k8s.io/apiserver` v0.34.1,
the same code as Kubernetes 1.34's kube-apiserver. The plugin runs against an
in-memory fake API holding your policies, bindings and the namespaces seen
so far. All of the following are the API server's code:

- matching: `matchConstraints`, namespace and object selectors, `matchConditions`
- `variables`, `validations` and `messageExpression`
- `failurePolicy`
- the CEL environment and its cost limits

CI checks the claim against a real API server, for each example policy:

1. Start a kind cluster running Kubernetes 1.34.
2. Bind the policy with every binding set to `[Audit]`. The server then
   admits everything, so the cluster follows the original history, but it
   records each failed validation in its own audit log.
3. Send the example's writes to it under their original audit IDs.
4. Compare, write by write, what the server recorded with what
   `admission-replay` concluded.

```
$ make crosscheck
...
sent 185 writes (0 rejected), skipped 13
registry-allowlist: 185 writes compared with the API server, 1 failed a validation on both sides, 0 disagreements
sent 185 writes (0 rejected), skipped 13
strict-baseline: 185 writes compared with the API server, 27 failed a validation on both sides, 0 disagreements
sent 185 writes (0 rejected), skipped 13
targeted: 185 writes compared with the API server, 24 failed a validation on both sides, 0 disagreements
```

The log's other 13 writes are the cluster's own: controllers creating each
namespace's `default` ServiceAccount and `kube-root-ca.crt` ConfigMap. They
are replayed, but they can't be resent, so they aren't part of the
comparison.

## Quickstart

You need Go 1.24 or newer.

```bash
git clone https://github.com/ahmed-hashim-pro/admission-replay.git
cd admission-replay
make build                       # a static binary, ./admission-replay

./admission-replay compare examples/audit.log examples/policies/*.yaml --bad examples/bad.txt
./admission-replay replay examples/audit.log examples/policies/strict-baseline.yaml --bad examples/bad.txt
./admission-replay check examples/policies/targeted.yaml
make test                        # about a minute the first time, most of it compiling
```

With Docker and no Go installed, build it in a container. The binary is
static, so it runs on the host:

```bash
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/w -w /w golang:1.25 make build
```

## One policy, write by write

`replay` lists what a single candidate did. It shows the legitimate writes
it blocked, grouped by user and by the validation that failed, then the bad
writes it let through and the ones it caught:

```
$ admission-replay replay examples/audit.log examples/policies/strict-baseline.yaml --bad examples/bad.txt --limit 3
examples/audit.log: 198 writes from 2026-09-01 to 2026-09-30 (29.2 days), 3 labelled bad
strict-baseline: binding strict-baseline -> policy strict-baseline (Deny)

BLOCKED 26 legitimate writes
  2026-09-01 10:12  ci-deploy  create deployments shop-staging/search
      strict-baseline: every container needs CPU and memory limits
      audit ID 5e9a0011-0000-4000-8000-000000000011
  2026-09-01 15:00  dana       create deployments platform/ingress-proxy
      strict-baseline: images must come from registry.example.com
      strict-baseline: pods must run as non-root
      audit ID 5e9a0023-0000-4000-8000-000000000023
  2026-09-01 15:10  dana       create deployments platform/cert-renewer
      strict-baseline: images must come from registry.example.com
      audit ID 5e9a0024-0000-4000-8000-000000000024
  ... 23 more (--limit 0 lists them all)
  by user:
      17  ci-deploy
       5  dana
       4  carol
  by failed validation:
      21  every container needs CPU and memory limits
       5  images must come from registry.example.com
       3  pods must run as non-root

LET THROUGH 2 of 3 bad writes
  2026-09-19 03:12  bob        update daemonsets monitoring/log-shipper
      labelled bad: log-shipper DaemonSet made privileged with the host's / mounted read-write
      admitted: no validation failed
      audit ID 5e9a0081-0000-4000-8000-000000000081
  2026-09-26 16:05  bob        update deployments shop-prod/checkout
      labelled bad: checkout gets a privileged init container (sysctl tweak)
      admitted: no validation failed
      audit ID 5e9a00a6-0000-4000-8000-0000000000a6

CAUGHT 1 of 3 bad writes
  2026-09-12 22:47  alice      update deployments shop-prod/payments
      labelled bad: payments hotfix image from a personal Docker Hub account
      strict-baseline: images must come from registry.example.com
      audit ID 5e9a005a-0000-4000-8000-00000000005a

```

Every failed validation is listed, not only the first. An API server stops
at the first denying failure. That's enough to reject a request, but when
you're fixing a policy you want all of them. A write that fails two
validations counts once under each in the "by failed validation" totals.

### The policy that holds

[`examples/policies/targeted.yaml`](examples/policies/targeted.yaml) holds
three policies:

- `no-host-escape` denies privileged containers and writable `hostPath`
  mounts. It checks every container list (`containers`, `initContainers`,
  `ephemeralContainers`) in Deployments, DaemonSets, StatefulSets and
  CronJobs.
- `trusted-images` denies images from outside a registry allowlist.
- `resource-limits` is bound with `[Warn, Audit]`.

`--fail-on-block` and `--fail-on-miss` turn the replay into a gate:

```
$ admission-replay replay examples/audit.log examples/policies/targeted.yaml --bad examples/bad.txt --show caught --fail-on-block --fail-on-miss
examples/audit.log: 198 writes from 2026-09-01 to 2026-09-30 (29.2 days), 3 labelled bad
targeted: binding no-host-escape -> policy no-host-escape (Deny)
targeted: binding trusted-images -> policy trusted-images (Deny)
targeted: binding resource-limits -> policy resource-limits (Warn, Audit)

CAUGHT 3 of 3 bad writes
  2026-09-12 22:47  alice      update deployments shop-prod/payments
      labelled bad: payments hotfix image from a personal Docker Hub account
      trusted-images: image docker.io/alice-dev/payments:hotfix-2 is not from a trusted registry
      audit ID 5e9a005a-0000-4000-8000-00000000005a
  2026-09-19 03:12  bob        update daemonsets monitoring/log-shipper
      labelled bad: log-shipper DaemonSet made privileged with the host's / mounted read-write
      no-host-escape: container shipper is privileged
      no-host-escape: hostPath volumes must be mounted read-only
      audit ID 5e9a0081-0000-4000-8000-000000000081
  2026-09-26 16:05  bob        update deployments shop-prod/checkout
      labelled bad: checkout gets a privileged init container (sysctl tweak)
      no-host-escape: container sysctl is privileged
      audit ID 5e9a00a6-0000-4000-8000-0000000000a6

```

The 21 writes it warns about are the loader and the staging search service,
which have no memory limit. They go through, and the people who own them
see the warning.

`check` parses a policy file the way `kubectl apply --validate=strict`
would, so a misspelt field is an error. It then compiles every CEL
expression with the API server's environment and names the field of any
that fail:

```
$ admission-replay check examples/policies/targeted.yaml
examples/policies/targeted.yaml: 3 policies, 3 bindings, every expression compiles
  binding no-host-escape -> policy no-host-escape (Deny)
  binding trusted-images -> policy trusted-images (Deny)
  binding resource-limits -> policy resource-limits (Warn, Audit)
```

## On your own cluster

**The log.** The API server needs an audit policy that records writes to the
resources your policy matches at `RequestResponse` level. At `Metadata`
level there's no object to replay. This one, from
[`hack/kind/audit-policy.yaml`](hack/kind/audit-policy.yaml), is what the
example used:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived", "ResponseStarted"]
rules:
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["namespaces", "services", "configmaps", "serviceaccounts"]
      - group: "apps"
        resources: ["deployments", "daemonsets", "statefulsets"]
      - group: "batch"
        resources: ["cronjobs"]
      - group: "networking.k8s.io"
        resources: ["ingresses", "networkpolicies"]
  - level: None
```

`--audit-log-path` writes the format `admission-replay` reads: one
`audit.k8s.io/v1` event per line. It also reads an `EventList` and gzip.
Managed control planes export audit events through their own logging
services, some in a different envelope. Get them back to one event per line
first.

**What happens to each write.**
- The object is the one the server stored (`responseObject`). Validating
  admission runs after mutation, so this is what it saw.
- The old object, for an update or delete, is the previous write to the same
  object in the log.
- The user is the impersonated user when there is one.
- Namespace labels change over the replay as the log changes them, so
  `namespaceSelector` sees each namespace as it was at that point.

**Objects older than the log.** A dump of the objects from when the log
starts gives their updates and deletes an old object to compare against.
Without it they're skipped, and the report says how many:

```bash
kubectl get namespaces,deployments,daemonsets,statefulsets,cronjobs -A -o yaml > initial.yaml
admission-replay replay audit.log policy.yaml --initial initial.yaml
```

**Labels.** `--bad` takes a file of audit IDs, each optionally followed by
a note: the writes an incident review says should never have got in. See
[`examples/bad.txt`](examples/bad.txt). An ID that isn't in the log is an
error, so a typo can't silently count as "missed".

**In CI.** On a pull request that changes a policy, run `replay` against a
recent log with `--fail-on-block` (no legitimate write in the window is
blocked) and `--fail-on-miss` (every labelled write is). `--json` gives
every verdict for further processing.

Exit status: 0 when nothing tripped, 1 when a `--fail-on` gate tripped,
2 for bad input.

## What this does not do

- **Only ValidatingAdmissionPolicy.** It doesn't replay validating or
  mutating webhooks (OPA Gatekeeper, Kyverno), MutatingAdmissionPolicy or
  Pod Security Admission. Their effects are already in the stored objects
  the replay uses. Their own decisions aren't replayed.
- **No `paramKind` / `paramRef` yet.** A policy that uses parameters is
  rejected with that message, not evaluated without them.
- **CEL's `authorizer` always says yes.** The replay has no RBAC, so it
  answers as it would for a cluster-admin. A policy that branches on
  `authorizer.…allowed()` is replayed as if every user may do everything.
- **The object is rebuilt, not captured.** `responseObject` is what
  admission saw, except for what storage sets afterwards: the new
  `resourceVersion`, and status a controller wrote in between. A policy that
  reads those can differ from the cluster. The crosscheck only covers the
  example policies, which don't read them.
- **Failed patches are skipped.** A rejected patch has no resulting object
  in the log, and the audit log doesn't record which patch type it was.
  Failed creates and updates are replayed from their request body, but they
  aren't counted as blocked, because the cluster had already refused them.
- **Kubernetes 1.34's admission code.** CEL gains functions between
  releases, so an expression that compiles here may not compile on an older
  API server. Run `check` against the version you run, or match it in
  `go.mod`.
- **The example is synthetic.** The company, the month and the three bad
  writes are invented. The audit log is real API server output, but no real
  cluster's traffic went into it.
- **It can't say a policy is good.** It shows how the policy would have
  treated the past. A policy only gets credit for catching what you labelled,
  and nothing marks an unlabelled bad write as missed.

The binary is about 70 MB, because it carries the API server's admission
and CEL stack.

## Development

```bash
make test          # vet and all tests
make check         # gofmt, vet, tests under -race
make docs          # rewrite docs/*.txt (the outputs this README quotes) from the CLI
make crosscheck    # the API server comparison above; needs Docker, kind and kubectl
make example       # re-record examples/audit.log on a throwaway kind cluster
make demo          # re-record docs/demo.gif with VHS in Docker
```

A test fails if a docs file is stale or this README stops quoting it.
`make example` generates the month's requests (`hack/genmonth`). It sends
them, as the users who made them, to a kind cluster that writes an audit log
(`hack/send`, `hack/kind`). It keeps that log, moved onto September's
calendar (`hack/retime`). Recording again gives new object UIDs and
resource versions, with the same verdicts.

## Layout

```
cmd/admission-replay/   the CLI: compare, replay, check
engine/                 the apiserver's ValidatingAdmissionPolicy plugin over an in-memory fake API
history/                audit log reader: audit.k8s.io/v1 events to replayable writes
replay/                 object state across the log, verdicts, scoring against labels
policy/                 strict loading of policy files; CEL compile check
examples/               the recorded month, its labels, three candidate policies
hack/                   the recording and the crosscheck: genmonth, send, retime, crosscheck, kind/
docs/                   the outputs the README quotes; demo.tape and demo.gif
```

## License

MIT
