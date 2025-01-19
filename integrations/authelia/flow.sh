#!/bin/sh
AUTHELIA_URL="https://127.0.0.1:9091"

# get code
curl -vk \
    -G \
    -d 'response_type=code' \
    -d 'client_id=test_client' \
    -d 'redirect_uri=http://127.0.0.1:8080/oauth2/callback' \
    -d 'state=aaaaaaaa' \
    -d 'nonce=bbbbbbbb' \
    -d 'scope=openid+profile+email+groups' \
    -d 'response_mode=query' \
    "${AUTHELIA_URL}/api/oidc/authorization" | tee /tmp/auth_resp

# receive redirect
printf 'HTTP/1.1 200 OK\r\n\r\n' | nc -l 127.0.0.1 8080 | tee /tmp/auth_redir
auth_code=$(grep -oE 'code=[^&]+' /tmp/auth_redir | cut -d '=' -f 2)
echo "code = $auth_code"

# get token
curl -vk \
    -X POST \
    -u 'test_client:insecure_secret' \
    -F 'grant_type=authorization_code' \
    -F "code=${auth_code}" \
    -F 'redirect_uri=http://127.0.0.1:8080/oauth2/callback' \
    -F 'state=aaaaaaaa' \
    -F 'nonce=bbbbbbbb' \
    "${AUTHELIA_URL}/api/oidc/token" | tee /tmp/token_resp | jq

# id token
jq -r '.id_token' /tmp/token_resp | cut -d '.' -f 1 | base64 -d | jq
jq -r '.id_token' /tmp/token_resp | cut -d '.' -f 2 | base64 -d | jq
