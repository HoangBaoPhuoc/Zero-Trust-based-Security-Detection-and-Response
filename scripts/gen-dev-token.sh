#!/usr/bin/env bash
# Generate a HS256 dev JWT token for testing the API gateway.
# Usage: ./gen-dev-token.sh [username] [role]
# Requires: python3 + PyJWT (pip install pyjwt)

set -euo pipefail

USERNAME="${1:-testuser01}"
ROLE="${2:-financial-write}"
JWT_SECRET="${JWT_DEV_SECRET:-ztlab-dev-secret}"
ISSUER="${JWT_ISSUER:-https://keycloak.ztlab.local/realms/ztlab}"
AUDIENCE="${JWT_AUDIENCE:-api-gateway}"
TTL_SECONDS="${JWT_TTL:-3600}"

TOKEN=$(python3 - "$USERNAME" "$ROLE" "$JWT_SECRET" "$ISSUER" "$AUDIENCE" "$TTL_SECONDS" <<'PY'
import sys, time, json
try:
    import jwt as pyjwt
    username, role, secret, issuer, audience, ttl = sys.argv[1:]
    now = int(time.time())
    payload = {
        "sub": username,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + int(ttl),
        "preferred_username": username,
        "realm_access": {"roles": [role]},
    }
    token = pyjwt.encode(payload, secret, algorithm="HS256")
    print(token)
except ImportError:
    # Fallback: manual HS256 if PyJWT not installed
    import base64, hmac, hashlib
    def b64url(data):
        if isinstance(data, str): data = data.encode()
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    username, role, secret, issuer, audience, ttl = sys.argv[1:]
    now = int(time.time())
    header = b64url(json.dumps({"alg":"HS256","typ":"JWT"}))
    payload = b64url(json.dumps({
        "sub": username, "iss": issuer, "aud": audience,
        "iat": now, "exp": now + int(ttl),
        "preferred_username": username,
        "realm_access": {"roles": [role]},
    }))
    signing_input = f"{header}.{payload}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    print(f"{signing_input}.{b64url(sig)}")
PY
)

echo "$TOKEN"
echo ""
echo "# Usage:"
echo "# curl -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:8080/payments ..."
echo ""
echo "# Or export:"
echo "export TOKEN='$TOKEN'"
