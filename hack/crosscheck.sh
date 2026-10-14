#!/usr/bin/env bash
# Check admission-replay against a real API server: for each candidate in
# examples/policies, start a kind cluster, bind the candidate with every
# binding in Audit mode, send examples/audit.log's writes to it with their
# original audit IDs, and compare the server's audit log with the replay.
#
# Needs Docker, kind and kubectl, and the Go tools built into $BIN
# (make tools).
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=${BIN:-build/bin}
CLUSTER=admission-replay-crosscheck
KCFG=build/crosscheck.kubeconfig
mkdir -p build
trap 'kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true' EXIT

status=0
for policy in ${POLICIES:-examples/policies/*.yaml}; do
  name=$(basename "$policy" .yaml)
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  kind create cluster --name "$CLUSTER" --config hack/kind/cluster.yaml --kubeconfig "$KCFG" --wait 120s >/dev/null 2>&1
  kubectl --kubeconfig "$KCFG" create clusterrolebinding everyone-is-admin \
    --clusterrole=cluster-admin --group=system:authenticated >/dev/null
  "$BIN/crosscheck" -policy "$policy" -print-audit-only | kubectl --kubeconfig "$KCFG" apply -f - >/dev/null
  # The admission plugin picks policies up from an informer and recompiles
  # them on a one-second tick.
  sleep 5
  "$BIN/send" -kubeconfig "$KCFG" -log examples/audit.log -results "build/crosscheck-$name.results"
  sleep 2
  docker exec "$CLUSTER-control-plane" cat /var/log/kubernetes/audit.log > "build/crosscheck-$name.audit.log"
  "$BIN/crosscheck" -log examples/audit.log -policy "$policy" -server "build/crosscheck-$name.audit.log" || status=1
done
exit $status
