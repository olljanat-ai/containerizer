#!/bin/bash
# In CI, inside the appliance: phase "prepare" makes a second snapshot (a copy of the running one, as an
# upgrade would) and leaves a marker on the persistent partition; phase "rollback" asks the system agent
# to roll back to snapshot 1, as the System page does; phase "verify" checks the result after the restart.
set -euo pipefail
PY=/usr/lib/containerizer/venv/bin/python
active() { $PY -c "import json; print([s['id'] for s in json.load(open('/run/containerizer/system/status.json'))['snapshots'] if s['active']][0])"; }
$PY -m containerizer.sysagent status >/dev/null
case "$1" in
  prepare)
    echo "marker $(date -u +%s)" > /var/lib/containerizer/ci-marker
    a=$(active); echo "active snapshot: $a"
    mount -o remount,rw /.snapshots || true
    elemental upgrade --system "dir:/.snapshots/$a/snapshot" --snapshot-labels version=ci-copy
    ;;
  rollback)
    a=$(active); echo "active snapshot: $a"; test "$a" = 2
    $PY - <<'PY'
import json, time, pathlib
r = pathlib.Path("/run/containerizer/system/requests")
(r / ".ci.tmp").write_text(json.dumps({"action": "rollback", "snapshot": 1, "requested_by": "ci"}))
(r / ".ci.tmp").rename(r / f"{int(time.time()*1000)}-ci.json")
PY
    ;;
  verify)
    $PY -c "
import json
st = json.load(open('/run/containerizer/system/status.json'))
print(json.dumps(st['snapshots'], indent=1)); print(st['task'])
act = [s for s in st['snapshots'] if s['active']][0]
assert act['id'] == 3 and act['labels'].get('rollback-of') == '1', act
assert st['task']['action'] == 'rollback' and st['task']['state'] == 'done', st['task']
"
    test -s /var/lib/containerizer/ci-marker
    for _ in $(seq 120); do curl -fsS http://127.0.0.1:8080/healthz && break; sleep 10; done
    curl -fsS http://127.0.0.1:8080/healthz
    echo "ROLLBACK CHECKS PASSED"
    ;;
esac
