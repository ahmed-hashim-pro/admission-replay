#!/usr/bin/env bash
# Regenerate examples/audit.log: generate the month's requests, send them to
# a throwaway kind cluster that writes an audit log, and keep that log.
#
# Needs Docker, kind and kubectl; the Go tools must already be built into
# $BIN (make tools does that).
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=${BIN:-build/bin}
CLUSTER=admission-replay-record
KCFG=build/record.kubeconfig
mkdir -p build

"$BIN/genmonth" -out build/plan.ndjson -bad examples/bad.txt

kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --config hack/kind/cluster.yaml --kubeconfig "$KCFG" --wait 120s
trap 'kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true' EXIT

# Every impersonated user is a cluster-admin here: the example is about
# admission, not RBAC, and it makes CEL's authorizer checks answer "yes",
# as admission-replay's do.
kubectl --kubeconfig "$KCFG" create clusterrolebinding everyone-is-admin \
  --clusterrole=cluster-admin --group=system:authenticated >/dev/null

# A second apart, so each object timestamp (1 s resolution) can be traced to
# the request that set it when hack/retime moves the log onto the plan's month.
"$BIN/send" -kubeconfig "$KCFG" -log build/plan.ndjson -pace 1050ms -results build/record-results.txt
if awk '$2 >= 300' build/record-results.txt | grep -q .; then
  echo "the recording cluster rejected requests:" >&2
  awk '$2 >= 300' build/record-results.txt >&2
  exit 1
fi

# Let the controllers finish reacting, then take the log.
sleep 20
docker exec "$CLUSTER-control-plane" cat /var/log/kubernetes/audit.log > build/raw-audit.log
"$BIN/retime" -plan build/plan.ndjson -in build/raw-audit.log -out examples/audit.log
