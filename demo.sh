#!/usr/bin/env bash
#
# Runnable proof for the OpenBao variant of CB4A Mode 3 (see README.md).
#
# It starts a throwaway OpenBao dev server, sets up:
#   - transit with per-user derived keys (check 1: crypto binding)
#   - jwt auth against a local test IdP key (the "broker" that verifies users)
#   - a templated policy so a login token only reaches its own user's key
#   - one-shot tokens: token_ttl=60s, token_num_uses=1
#   - an encrypt-only "controller" identity
# and runs 10 checks:
#   1-6  the core Mode 3 properties
#   7    token TTL expires on the wall clock
#   8    token_bound_cidrs blocks the wrong source IP
#   9    dynamic Postgres credentials: mint, use, revoke (needs docker + psql, skipped otherwise)
#   10   audit fail-closed: no log, no request (needs macOS hdiutil, skipped otherwise)
#
# Requirements: bao, openssl, jq. Checks 9 and 10 have extra requirements and
# report SKIP when those are missing. Everything runs on 127.0.0.1.

set -u

PORT=8299
export BAO_ADDR="http://127.0.0.1:${PORT}"
export BAO_TOKEN=root
WORK=$(mktemp -d)
PG_CONTAINER=bao-demo-pg
RAMDISK_VOL=BAODEMO
PASS=0
FAIL=0
SKIP=0

cleanup() {
  [ -n "${BAO_PID:-}" ] && kill "$BAO_PID" 2>/dev/null
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1
  diskutil eject "$RAMDISK_VOL" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# mkjwt <sub> <exp-epoch>  ->  RS256 JWT signed with the local test IdP key
mkjwt() {
  local sub=$1 exp=$2 now
  now=$(date +%s)
  local header payload sig
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  payload=$(printf '{"iss":"https://idp.local","aud":"agentgateway","sub":"%s","iat":%s,"exp":%s}' "$sub" "$now" "$exp" | b64url)
  sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$WORK/idp.key" -binary | b64url)
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}

# check <name> <expected-substring> <actual-output>
check() {
  local name=$1 want=$2 got=$3
  if printf '%s' "$got" | grep -q "$want"; then
    printf 'PASS  %s\n' "$name"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %s\n      wanted: %s\n      got: %s\n' "$name" "$want" "$got"
    FAIL=$((FAIL + 1))
  fi
}

skip() {
  printf 'SKIP  %s (%s)\n' "$1" "$2"
  SKIP=$((SKIP + 1))
}

echo "== starting OpenBao dev server on ${BAO_ADDR}"
# the flag lets check 10 enable an audit device through the API
printf 'unsafe_allow_api_audit_creation = true\n' >"$WORK/server.hcl"
bao server -dev -dev-root-token-id=root -dev-listen-address="127.0.0.1:${PORT}" \
  -config="$WORK/server.hcl" >"$WORK/server.log" 2>&1 &
BAO_PID=$!
for _ in $(seq 1 20); do
  bao status >/dev/null 2>&1 && break
  sleep 0.5
done
bao status >/dev/null || { echo "server did not come up, see $WORK/server.log"; exit 1; }

echo "== setup: transit, jwt auth, policies"
openssl genrsa -out "$WORK/idp.key" 2048 2>/dev/null
openssl rsa -in "$WORK/idp.key" -pubout -out "$WORK/idp.pub" 2>/dev/null

bao secrets enable transit >/dev/null
bao write -f transit/keys/user-alice derived=true type=aes256-gcm96 >/dev/null
bao write -f transit/keys/user-bob   derived=true type=aes256-gcm96 >/dev/null

bao auth enable jwt >/dev/null
bao write auth/jwt/config jwt_validation_pubkeys=@"$WORK/idp.pub" >/dev/null
ACCESSOR=$(bao auth list -format=json | jq -r '.["jwt/"].accessor')

cat >"$WORK/decrypt-own.hcl" <<EOF
path "transit/decrypt/user-{{identity.entity.aliases.${ACCESSOR}.name}}" {
  capabilities = ["update"]
}
EOF
bao policy write decrypt-own "$WORK/decrypt-own.hcl" >/dev/null

bao write auth/jwt/role/agent-egress role_type=jwt user_claim=sub \
  bound_audiences=agentgateway token_policies=decrypt-own \
  token_ttl=60s token_num_uses=1 >/dev/null

# extra roles for checks 7 and 8
bao write auth/jwt/role/ttl-test role_type=jwt user_claim=sub \
  bound_audiences=agentgateway token_policies=decrypt-own token_ttl=5s >/dev/null
bao write auth/jwt/role/cidr-block role_type=jwt user_claim=sub \
  bound_audiences=agentgateway token_policies=decrypt-own \
  token_ttl=60s token_bound_cidrs=192.0.2.0/24 >/dev/null

# the controller can wrap (encrypt) but has no decrypt path of its own
cat >"$WORK/controller.hcl" <<'EOF'
path "transit/encrypt/user-*" { capabilities = ["update"] }
EOF
bao policy write controller "$WORK/controller.hcl" >/dev/null
CTRL_TOKEN=$(bao token create -field=token -policy=controller)

# stored rows: one credential per user, context = owner + row id
CTX_A=$(printf 'alice|row-123' | base64)
CTX_B=$(printf 'bob|row-456' | base64)
CT_A=$(bao write -field=ciphertext transit/encrypt/user-alice \
  plaintext=$(printf 'alice-github-token' | base64) context="$CTX_A")
CT_B=$(bao write -field=ciphertext transit/encrypt/user-bob \
  plaintext=$(printf 'bob-github-token' | base64) context="$CTX_B")

echo "== checks"

# 1) crypto binding: alice's row with bob's context fails the AEAD open
OUT=$(bao write transit/decrypt/user-alice ciphertext="$CT_A" context="$CTX_B" 2>&1)
check "1 derived context binding rejects wrong owner" "message authentication failed" "$OUT"

# 2) the happy path: subject JWT -> jwt/login -> one-shot token -> own row decrypts
NOW=$(date +%s)
mkjwt alice $((NOW + 300)) >"$WORK/alice.jwt"
TOKEN=$(bao write -field=token auth/jwt/login role=agent-egress jwt=@"$WORK/alice.jwt")
[ -n "$TOKEN" ] || { echo "FAIL  2 login returned no token"; exit 1; }
OUT=$(env BAO_TOKEN="$TOKEN" bao write -field=plaintext \
  transit/decrypt/user-alice ciphertext="$CT_A" context="$CTX_A" | base64 -d)
check "2 verified user decrypts own row" "alice-github-token" "$OUT"

# 3) the same token a second time: num_uses=1 already consumed it
OUT=$(env BAO_TOKEN="$TOKEN" bao write transit/decrypt/user-alice \
  ciphertext="$CT_A" context="$CTX_A" 2>&1)
check "3 one-shot token dies on reuse" "permission denied" "$OUT"

# 4) a fresh alice token against bob's key path: policy scope blocks it
TOKEN2=$(bao write -field=token auth/jwt/login role=agent-egress jwt=@"$WORK/alice.jwt")
OUT=$(env BAO_TOKEN="$TOKEN2" bao write transit/decrypt/user-bob \
  ciphertext="$CT_B" context="$CTX_B" 2>&1)
check "4 cross-user decrypt denied" "permission denied" "$OUT"

# 5) the controller's own identity, raw decrypt on a real row
OUT=$(env BAO_TOKEN="$CTRL_TOKEN" bao write transit/decrypt/user-bob \
  ciphertext="$CT_B" context="$CTX_B" 2>&1)
check "5 ciphertext holder cannot decrypt alone" "permission denied" "$OUT"

# 6) an expired subject JWT never gets a token
mkjwt alice $((NOW - 60)) >"$WORK/expired.jwt"
OUT=$(bao write auth/jwt/login role=agent-egress jwt=@"$WORK/expired.jwt" 2>&1)
check "6 expired subject token rejected at login" "expired" "$OUT"

# 7) token TTL is enforced on the wall clock: a 5s token dies by itself
TOKEN3=$(bao write -field=token auth/jwt/login role=ttl-test jwt=@"$WORK/alice.jwt")
OUT=$(env BAO_TOKEN="$TOKEN3" bao write -field=plaintext \
  transit/decrypt/user-alice ciphertext="$CT_A" context="$CTX_A" | base64 -d)
if [ "$OUT" = "alice-github-token" ]; then
  sleep 8
  OUT=$(env BAO_TOKEN="$TOKEN3" bao write transit/decrypt/user-alice \
    ciphertext="$CT_A" context="$CTX_A" 2>&1)
  check "7 token expires after its TTL" "permission denied" "$OUT"
else
  echo "FAIL  7 fresh ttl-test token could not decrypt"; FAIL=$((FAIL + 1))
fi

# 8) token_bound_cidrs: a role bound to 192.0.2.0/24 refuses a 127.0.0.1 caller at login
OUT=$(bao write auth/jwt/login role=cidr-block jwt=@"$WORK/alice.jwt" 2>&1)
check "8 CIDR-bound role rejects wrong source IP" "permission denied" "$OUT"

# 9) dynamic secrets: mint a 120s Postgres credential, use it, revoke it
if docker info >/dev/null 2>&1 && command -v psql >/dev/null 2>&1; then
  docker run -d --name "$PG_CONTAINER" -e POSTGRES_USER=bao_admin \
    -e POSTGRES_PASSWORD=adminpw -p 127.0.0.1:5499:5432 postgres:17-alpine >/dev/null
  PG_UP=""
  for _ in $(seq 1 30); do
    PGPASSWORD=adminpw psql -h 127.0.0.1 -p 5499 -U bao_admin -d postgres \
      -tAc "select 1" >/dev/null 2>&1 && { PG_UP=1; break; }
    sleep 1
  done
  if [ -n "$PG_UP" ]; then
    bao secrets enable database >/dev/null
    bao write database/config/pg plugin_name=postgresql-database-plugin \
      connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:5499/postgres?sslmode=disable" \
      allowed_roles=app username=bao_admin password=adminpw >/dev/null
    bao write database/roles/app db_name=pg default_ttl=120s max_ttl=300s \
      creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE postgres TO \"{{name}}\";" >/dev/null
    CREDS=$(bao read -format=json database/creds/app)
    DBUSER=$(printf '%s' "$CREDS" | jq -r .data.username)
    DBPASS=$(printf '%s' "$CREDS" | jq -r .data.password)
    LEASE=$(printf '%s' "$CREDS" | jq -r .lease_id)
    LOGIN1=$(PGPASSWORD=$DBPASS psql -h 127.0.0.1 -p 5499 -U "$DBUSER" -d postgres \
      -tAc "select current_user" 2>&1)
    bao lease revoke "$LEASE" >/dev/null
    sleep 3
    LOGIN2=$(PGPASSWORD=$DBPASS psql -h 127.0.0.1 -p 5499 -U "$DBUSER" -d postgres \
      -tAc "select 1" 2>&1)
    LEFT=$(PGPASSWORD=adminpw psql -h 127.0.0.1 -p 5499 -U bao_admin -d postgres \
      -tAc "select count(*) from pg_roles where rolname='$DBUSER'")
    if [ "$LOGIN1" = "$DBUSER" ] && printf '%s' "$LOGIN2" | grep -q "authentication failed" && [ "$LEFT" = "0" ]; then
      echo "PASS  9 dynamic credential minted, used, revoked, role dropped"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  9 dynamic credential cycle\n      login1: %s\n      login2: %s\n      roles left: %s\n' "$LOGIN1" "$LOGIN2" "$LEFT"
      FAIL=$((FAIL + 1))
    fi
  else
    skip "9 dynamic Postgres credential cycle" "postgres container did not come up"
  fi
else
  skip "9 dynamic Postgres credential cycle" "needs a running docker daemon and psql"
fi

# 10) audit fail-closed: fill the audit disk, requests must be refused
if [ "$(uname)" = "Darwin" ] && command -v hdiutil >/dev/null 2>&1; then
  RD=$(hdiutil attach -nomount ram://8192 | awk '{print $1}')
  diskutil eraseVolume HFS+ "$RAMDISK_VOL" "$RD" >/dev/null 2>&1
  bao audit enable file file_path="/Volumes/${RAMDISK_VOL}/audit.log" >/dev/null
  bao write -f transit/keys/audit-warmup type=aes256-gcm96 >/dev/null 2>&1
  dd if=/dev/zero of="/Volumes/${RAMDISK_VOL}/fill1" bs=64k 2>/dev/null
  dd if=/dev/zero of="/Volumes/${RAMDISK_VOL}/fill2" bs=512 2>/dev/null
  OUT=""
  for i in $(seq 1 40); do
    OUT=$(bao write -f transit/keys/audit-k$i type=aes256-gcm96 2>&1) || break
  done
  check "10 fail-closed: request refused when audit cannot write" "internal error" "$OUT"
else
  skip "10 audit fail-closed" "needs macOS hdiutil for the ram disk"
fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[ "$FAIL" -eq 0 ]
