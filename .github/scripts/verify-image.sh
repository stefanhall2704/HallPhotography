#!/usr/bin/env bash
# verify-image.sh <namespace> <app-label> <digest>
# Fails unless EVERY running (non-terminating) pod of the app runs the image that this commit just built.
# containerd reports a pod's imageID as repo@<top-level digest>, which is exactly build-push-action's `digest` output.
set -euo pipefail
ns=${1:?namespace}; app=${2:?app label}; want=${3:?digest}
[[ "$want" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "::error::'$want' is not a sha256 digest (did the build job export it?)"; exit 1; }
rc=1
for _ in $(seq 1 12); do                     # pods can take a moment to settle after rollout status returns
  pods=$(kubectl get pods -n "$ns" -l "app=$app" -o json \
         | jq -r '.items[] | select(.metadata.deletionTimestamp==null) | "\(.metadata.name) \(.status.containerStatuses[0].imageID // "pending")"')
  [ -n "$pods" ] || { echo "no running pods for $ns/$app"; sleep 5; continue; }
  rc=0; out=""
  while read -r p got; do
    if [ "${got##*@}" = "$want" ]; then out+="  OK   $ns/$p runs the image built by this commit (${want:0:19}...)"$'\n'
    else out+="  WAIT $ns/$p runs ${got##*@}"$'\n'; rc=1; fi
  done <<<"$pods"
  [ $rc = 0 ] && break; sleep 5
done
printf '%s' "$out"
[ $rc = 0 ] || { echo "::error::$ns/$app is not running the image built by this commit ($want)"; exit 1; }
