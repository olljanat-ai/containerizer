#!/usr/bin/env bash
# Run the GitHub workflow jobs on this machine, without GitHub: see docs/local-dev-server.md.
#
#   ci/local.sh                 the fast set: test docs gate selftest security sql sandbox
#   ci/local.sh all             everything: the fast set plus assess (about 1 h) and appliance (about 1-2 h)
#   ci/local.sh test sql        only the named jobs, in that order
#   ci/local.sh --list          the jobs and the workflow job each one mirrors
#
# Jobs keep going after a failure; the exit code is non-zero when any job failed, and a summary is
# printed at the end. Logs: .work/ci-local/logs/<job>.log. Containers and the kind cluster it creates
# are named cz-ci-* / cz-sandbox; KEEP=1 leaves them running for debugging.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_LOCAL_WORK:-$ROOT/.work/ci-local}
VENV=${CI_LOCAL_VENV:-$ROOT/.venv-ci}
PY_VERSION=${CI_LOCAL_PYTHON:-3.12}              # actions/setup-python in every workflow
CHALLENGE_REPO=${CHALLENGE_REPO:-https://github.com/onek8s/containerization-challenge}
SQL_PASSWORD='Ci-Only-Passw0rd!'                 # the same throwaway password as ci.yml; bound to 127.0.0.1 only
SQL_IMAGE=mcr.microsoft.com/mssql/server:2025-latest
SQL_PORT=${CI_LOCAL_SQL_PORT:-11433}            # CI uses 1433, which results/compose.yaml takes on this server
KIND_NAME=cz-sandbox
KEEP=${KEEP:-0}

FAST=(test docs gate selftest security sql sandbox)
ALL=(test docs gate security sql sandbox selftest assess appliance)
declare -A MIRRORS=(
  [test]="ci.yml test: unit tests"
  [docs]="docs.yml build: mkdocs build --strict"
  [gate]="ci.yml containerizer + containerizer-head: the action's gate on examples/ci-demo"
  [security]="security.yml gate: generate, build, lint and scan examples/ci-demo"
  [sql]="ci.yml sql: SQL Server tests, results image and web UI smoke test"
  [sandbox]="ci.yml sandbox: tests/test_sandbox_cluster.py on a kind cluster"
  [selftest]="ci.yml action-selftest: the gate fails on a Windows-only change to the challenge app"
  [assess]="ci.yml assess-oneshot: analyze the challenge apps, build and run what is generated"
  [appliance]="release.yml appliance: OS image, disk images, ISO, QEMU boot test (no push or signing)"
)

mkdir -p "$WORK/logs"
c_red=$'\e[31m' c_green=$'\e[32m' c_dim=$'\e[2m' c_off=$'\e[0m'
[ -t 1 ] || { c_red=; c_green=; c_dim=; c_off=; }
say() { echo "${c_dim}[ci-local]${c_off} $*"; }
die() { echo "${c_red}$*${c_off}" >&2; return 1; }
need() { for t in "$@"; do command -v "$t" >/dev/null || die "missing tool: $t (see docs/local-dev-server.md)" || return 1; done; }

# ------------------------------------------------------------------ python environment
venv() {
  # a venv made before uv was installed has the system Python (3.13 on Debian 13): rebuild it with uv
  if [ -x "$VENV/bin/python" ] && command -v uv >/dev/null &&
     ! "$VENV/bin/python" -c "import sys; sys.exit(f'{sys.version_info[0]}.{sys.version_info[1]}' != '$PY_VERSION')"; then
    say "$VENV has $("$VENV/bin/python" --version), CI uses $PY_VERSION: recreating it with uv"
    rm -rf "$VENV"
  fi
  if [ ! -x "$VENV/bin/python" ]; then
    if command -v uv >/dev/null; then
      say "creating $VENV with uv (Python $PY_VERSION)"
      uv venv -q --python "$PY_VERSION" "$VENV" || return 1
    else
      say "uv not found: creating $VENV with $(python3 --version) (CI uses $PY_VERSION)"
      python3 -m venv "$VENV" || return 1
    fi
  fi
  local stamp="$VENV/.ci-local-deps" sum
  sum=$(cat "$ROOT"/requirements.txt "$ROOT"/requirements-sql.txt | sha256sum | cut -c1-16)
  if [ "$(cat "$stamp" 2>/dev/null)" != "$sum" ]; then
    say "installing requirements into $VENV"
    if command -v uv >/dev/null; then
      uv pip install -q --python "$VENV/bin/python" -r "$ROOT/requirements.txt" -r "$ROOT/requirements-sql.txt" \
        pytest "mkdocs==1.6.1" "mkdocs-material==9.8.0" || return 1
    else
      "$VENV/bin/python" -m pip install -q --disable-pip-version-check -r "$ROOT/requirements.txt" \
        -r "$ROOT/requirements-sql.txt" pytest "mkdocs==1.6.1" "mkdocs-material==9.8.0" || return 1
    fi
    echo "$sum" > "$stamp"
  fi
  export PATH="$VENV/bin:$PATH"
}

docker_ok() { need docker && docker info >/dev/null 2>&1 || die "docker is not running, or this user is not in the docker group"; }

# outputs the action would write: run with GITHUB_OUTPUT pointing at a file, then read key=value back
out_of() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2-; }

challenge() {  # fresh shallow clone of the challenge repository, like actions/checkout
  rm -rf "$WORK/challenge"
  git clone -q --depth 1 "$CHALLENGE_REPO" "$WORK/challenge"
}

# ------------------------------------------------------------------ jobs
job_test() {
  cd "$ROOT" && python -m pytest -q
}

job_docs() {
  cd "$ROOT" && NO_MKDOCS_2_WARNING=1 mkdocs build --strict -q -d "$WORK/site"
}

job_gate() {
  cd "$ROOT"
  local o="$WORK/gate" base
  rm -rf "$o"; mkdir -p "$o"
  # containerizer: no base on a push. containerizer-head: compare with the merge base of the PR branch.
  GITHUB_OUTPUT="$o/out-push" python -m containerizer check examples/ci-demo --max-rating B \
    --markdown "$o/push.md" --sarif "$o/push.sarif" --json "$o/push.json" || return 1
  say "push: rating=$(out_of "$o/out-push" rating) new=$(out_of "$o/out-push" new-findings)"
  git fetch -q origin main 2>/dev/null || true
  base=$(git merge-base HEAD origin/main 2>/dev/null) || { say "no origin/main: skipping the head comparison"; return 0; }
  GITHUB_OUTPUT="$o/out-head" python -m containerizer check examples/ci-demo --base-ref "$base" \
    --markdown "$o/head.md" --sarif "$o/head.sarif" --json "$o/head.json" || return 1
  say "head vs ${base:0:12}: rating=$(out_of "$o/out-head" rating) new=$(out_of "$o/out-head" new-findings)"
}

job_security() {
  docker_ok || return 1
  cd "$ROOT" && python -m containerizer gate examples/ci-demo --out "$WORK/security"
}

sql_up() {
  docker rm -f cz-ci-mssql >/dev/null 2>&1
  say "starting SQL Server ($SQL_IMAGE) on 127.0.0.1:$SQL_PORT"
  docker run -d --name cz-ci-mssql -p 127.0.0.1:$SQL_PORT:1433 \
    -e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e MSSQL_SA_PASSWORD="$SQL_PASSWORD" \
    --health-cmd "/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P '$SQL_PASSWORD' -Q 'SELECT 1' -b -o /dev/null" \
    --health-interval 10s --health-timeout 5s --health-retries 20 --health-start-period 20s \
    "$SQL_IMAGE" >/dev/null || return 1
  for _ in $(seq 60); do
    case $(docker inspect -f '{{.State.Health.Status}}' cz-ci-mssql 2>/dev/null) in
      healthy) return 0 ;;
      unhealthy) docker logs cz-ci-mssql | tail -30; return 1 ;;
    esac
    sleep 5
  done
  die "SQL Server did not become healthy"
}

job_sql() {
  docker_ok || return 1
  sql_up || return 1
  cd "$ROOT"
  local rc=0
  CONTAINERIZER_TEST_SQL="Server=127.0.0.1,$SQL_PORT;Database=master;User Id=sa;TrustServerCertificate=yes" \
  CONTAINERIZER_SQL_PASSWORD="$SQL_PASSWORD" \
    python -m pytest -q tests/test_sqlstore.py tests/test_admin.py tests/test_roles.py tests/test_trends.py \
      tests/test_sandbox.py tests/test_worker.py tests/test_sbom.py tests/test_devdb.py tests/test_rule_review.py -rs || rc=1
  if [ $rc = 0 ]; then
    say "image builds and the UI serves results"
    (
      set -e
      docker build -q -f results/Dockerfile -t containerizer-results . >/dev/null
      export CONTAINERIZER_SQL="Server=127.0.0.1,$SQL_PORT;Database=Containerizer;User Id=sa;TrustServerCertificate=yes"
      export CONTAINERIZER_SQL_PASSWORD="$SQL_PASSWORD" CZ_CZ_WEB_PASSWORD='Ci-Web-Passw0rd!'
      python -m containerizer db init --create-database --login cz_web:reader
      python -m containerizer assess -q examples/ci-demo
      docker rm -f cz-ci-web >/dev/null 2>&1 || true
      # CI uses port 8080; 18080 here so it does not clash with anything you run yourself
      docker run -d --name cz-ci-web --network host -e CONTAINERIZER_SQL_PASSWORD="$CZ_CZ_WEB_PASSWORD" \
        -e CONTAINERIZER_SQL="Server=127.0.0.1,$SQL_PORT;Database=Containerizer;User Id=cz_web;TrustServerCertificate=yes" \
        --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp \
        containerizer-results web --host 127.0.0.1 --port 18080 >/dev/null
      for _ in $(seq 30); do curl -fsS http://127.0.0.1:18080/healthz >/dev/null && break; sleep 1; done
      curl -fsS http://127.0.0.1:18080/ | grep -q ci-demo || { docker logs cz-ci-web; exit 1; }
      curl -fsS http://127.0.0.1:18080/trends | grep -q ci-demo || { docker logs cz-ci-web; exit 1; }
      curl -fsS http://127.0.0.1:18080/sbom | grep -q "Components with an SBOM" || { docker logs cz-ci-web; exit 1; }
    )
    rc=$?   # not "( ... ) || rc=1": that would switch off set -e inside the subshell
  fi
  [ "$KEEP" = 1 ] || docker rm -f cz-ci-web cz-ci-mssql >/dev/null 2>&1
  return $rc
}

job_sandbox() {
  docker_ok && need kind kubectl || return 1
  local kc="$WORK/kubeconfig-$KIND_NAME" created=0 rc=0
  if ! kind get clusters 2>/dev/null | grep -qx "$KIND_NAME"; then
    say "creating kind cluster $KIND_NAME"
    kind create cluster --name "$KIND_NAME" --wait 120s || return 1
    created=1
  fi
  kind get kubeconfig --name "$KIND_NAME" > "$kc" && chmod 600 "$kc"
  cd "$ROOT" && CONTAINERIZER_TEST_KUBE="$kc" python -m pytest -q tests/test_sandbox_cluster.py -rs -s || rc=1
  [ "$KEEP" = 1 ] || [ $created = 0 ] || kind delete cluster -q --name "$KIND_NAME"
  return $rc
}

job_selftest() {
  need git || return 1
  challenge || return 1
  local o="$WORK/selftest" app=scenarios/parts-catalog/src/PartsCatalog rc_bad=0
  rm -rf "$o"; mkdir -p "$o"
  (
    set -e
    cd "$WORK/challenge"
    git config user.email ci@example.com && git config user.name ci
    sed -i 's#<PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.11" />#&\n    <PackageReference Include="Microsoft.Win32.Registry" Version="5.0.0" />#' $app/PartsCatalog.csproj
    printf '\nstatic class Settings { public static object? Get() => Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\\\\Parts"); }\n' >> $app/Program.cs
    printf '\nstatic class Printing { public static void Print() { var d = new System.Drawing.Printing.PrintDocument(); var o = Type.GetTypeFromProgID("Excel.Application"); } }\n' >> $app/Program.cs
    git commit -qam "use the registry and Excel"
  )
  [ $? = 0 ] || return 1
  cd "$WORK"
  GITHUB_OUTPUT="$o/out-bad" PYTHONPATH="$ROOT" python -m containerizer check challenge/scenarios/parts-catalog \
    --base-ref HEAD~1 --sarif "$o/bad.sarif" --json "$o/bad.json" --markdown "$o/bad.md" || rc_bad=$?
  GITHUB_OUTPUT="$o/out-good" PYTHONPATH="$ROOT" python -m containerizer check challenge/scenarios/expense-claims \
    --base-ref HEAD~1 --max-rating B --sarif "$o/good.sarif" --json "$o/good.json" --markdown "$o/good.md"
  local rc_good=$?
  say "bad: rc=$rc_bad failed=$(out_of "$o/out-bad" failed) rating=$(out_of "$o/out-bad" rating)"
  say "good: rc=$rc_good failed=$(out_of "$o/out-good" failed) rating=$(out_of "$o/out-good" rating)"
  test $rc_bad = 1 && test "$(out_of "$o/out-bad" failed)" = true || die "the gate did not fail on the bad change" || return 1
  test "$(out_of "$o/out-good" failed)" = false && test "$(out_of "$o/out-good" rating)" = B \
    || die "the unchanged app did not pass at B" || return 1
  python -c "import json,sys; r=json.load(open(sys.argv[1]))['runs'][0]['results']; assert any(x.get('baselineState')=='new' for x in r), r" "$o/bad.sarif"
}

job_assess() {
  docker_ok && need git || return 1
  challenge || return 1
  local out="$WORK/assess" o="$WORK/assess-outputs"
  rm -rf "$out" "$o"; mkdir -p "$out" "$o"
  cd "$WORK"
  local paths=(challenge/scenarios/parts-catalog challenge/scenarios/expense-claims challenge/scenarios/batch-release)
  # the action's Check step (no base outside a pull request), then Assess, generate and verify
  GITHUB_OUTPUT="$o/check" PYTHONPATH="$ROOT" python -m containerizer check "${paths[@]}" --sarif "$o/assess.sarif" \
    --json "$o/check.json" --markdown "$o/check.md"
  [ $? -le 1 ] || return 1
  PYTHONPATH="$ROOT" python -m containerizer analyze "${paths[@]}" --out "$out" --timeout 1800 | tee "$out/analyze.log"
  [ "${PIPESTATUS[0]}" = 0 ] || return 1
  PYTHONPATH="$ROOT" python -m containerizer.ci summary "$out" > "$out/summary.md"
  local rating unconfirmed
  rating=$(out_of "$o/check" rating)
  unconfirmed=$(PYTHONPATH="$ROOT" python -m containerizer.ci unconfirmed "$out")
  say "rating=$rating unconfirmed=$unconfirmed (summary: $out/summary.md)"
  test -f "$out/portfolio.md" && test -d "$out/parts-catalog" || die "report files missing" || return 1
  python -c "import json,sys; a={x['name']: x for x in json.load(open(sys.argv[1]))}; v=a['parts-catalog'].get('verification') or []; print(v); assert any(r['status'].startswith('ok') for r in v)" "$out/assessment.json" || return 1
  test "$rating" = D || die "rating $rating, expected D (worst of B, B and D)" || return 1
  test "$unconfirmed" = 0 || die "$unconfirmed component(s) predicted ready did not build or run"
}

job_appliance() {
  docker_ok && need qemu-system-x86_64 qemu-img ssh-keygen ssh curl || return 1
  [ -r /usr/share/OVMF/OVMF_CODE_4M.fd ] || die "missing /usr/share/OVMF/OVMF_CODE_4M.fd: apt install ovmf" || return 1
  [ -w /dev/kvm ] || die "/dev/kvm is not writable: add this user to the kvm group (and enable nested virtualization in a VM)" || return 1
  docker buildx version >/dev/null 2>&1 || die "docker buildx is missing: apt install docker-buildx-plugin" || return 1
  cd "$ROOT"
  local v="ci-$(git rev-parse --short=12 HEAD)" b="$WORK/appliance"
  say "building the OS image (version $v)"
  docker buildx build -f appliance/Dockerfile --load -t containerizer-appliance:build \
    --build-arg VERSION="$v" --build-arg IMAGE=ghcr.io/olljanat-ai/containerizer-appliance \
    --build-arg SIGNER_REPO=olljanat-ai/containerizer . || return 1
  # elemental writes as root: clean up and hand the files back through a container, so no sudo is needed
  [ -d "$b" ] && docker run --rm -v "$WORK:/w" --entrypoint /bin/rm containerizer-appliance:build -rf /w/appliance
  mkdir -p "$b/test"
  ssh-keygen -q -t ed25519 -N '' -f "$b/ci_key"
  sed "s#@KEY@#$(cat "$b/ci_key.pub")#" appliance/ci/test-login.yaml.in > "$b/test-login.yaml"
  run_elemental() {
    docker run --rm --privileged -v /dev:/dev -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$b:/build" --entrypoint /usr/bin/elemental containerizer-appliance:build --debug "$@"
  }
  (
    set -e
    run_elemental build-disk --expandable --local --system containerizer-appliance:build -n "containerizer-$v" -o /build
    run_elemental build-disk --expandable --local --system containerizer-appliance:build \
      --cloud-init /build/test-login.yaml -n test -o /build/test
    run_elemental build-iso --local --bootloader-in-rootfs --extra-cmdline "console=tty1 console=ttyS0" \
      -n "containerizer-$v" -o /build containerizer-appliance:build
  ) > "$WORK/logs/appliance-elemental.log" 2>&1
  [ $? = 0 ] || { tail -50 "$WORK/logs/appliance-elemental.log"; return 1; }
  docker run --rm -v "$b:/build" --entrypoint /bin/chown containerizer-appliance:build -R "$(id -u):$(id -g)" /build
  ls -la "$b" "$b/test"
  OUT="$b/boot" appliance/ci/boot-test.sh "$b/test/test.raw" "$b/ci_key"
}

# ------------------------------------------------------------------ main
if [ "${1:-}" = "--list" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  for j in "${ALL[@]}"; do printf '  %-10s %s\n' "$j" "${MIRRORS[$j]}"; done
  echo "default: ${FAST[*]}"
  exit 0
fi
jobs=("$@")
[ ${#jobs[@]} = 0 ] && jobs=("${FAST[@]}")
[ "${jobs[*]}" = all ] && jobs=("${ALL[@]}")
for j in "${jobs[@]}"; do
  [ -n "${MIRRORS[$j]:-}" ] || { echo "unknown job: $j (try --list)" >&2; exit 2; }
done

venv || { die "could not set up the Python environment"; exit 1; }
declare -A RESULT TIME
failed=0
for j in "${jobs[@]}"; do
  log="$WORK/logs/$j.log"
  say "=== $j: ${MIRRORS[$j]}  (log: ${log#"$ROOT"/})"
  start=$SECONDS
  ( "job_$j" ) 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  TIME[$j]=$((SECONDS - start))
  if [ "$rc" = 0 ]; then RESULT[$j]="${c_green}pass${c_off}"; else RESULT[$j]="${c_red}FAIL${c_off}"; failed=1; fi
done
echo
say "summary"
for j in "${jobs[@]}"; do printf '  %-10s %s  %ss\n' "$j" "${RESULT[$j]}" "${TIME[$j]}"; done
exit $failed
