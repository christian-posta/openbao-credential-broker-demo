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
# and runs 6 checks. All 6 must pass.
#
# Requirements: bao, openssl, jq. Everything runs on 127.0.0.1, nothing leaves the machine.

set -u

PORT=8299
export BAO_ADDR="http://127.0.0.1:${PORT}"
export BAO_TOKEN=root
WORK=$(mktemp -d)
PASS=0
FAIL=0

cleanup() {
  [ -n "${BAO_PID:-}" ] && kill "$BAO_PID" 2>/dev/null
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

echo "== starting OpenBao dev server on ${BAO_ADDR}"
bao server -dev -dev-root-token-id=root -dev-listen-address="127.0.0.1:${PORT}" >"$WORK/server.log" 2>&1 &
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

echo
echo "${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
