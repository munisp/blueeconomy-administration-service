#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
integration="$root/integration"
compose=(sudo docker compose --env-file "$integration/.env" -f "$integration/compose.yaml")
service_pid=""

cleanup() {
  if [[ -n "$service_pid" ]] && kill -0 "$service_pid" 2>/dev/null; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null || { echo "required command missing: $1" >&2; exit 1; }
}
for command in curl jq openssl go sudo docker; do require "$command"; done

umask 077
rm -f "$integration/.env" "$integration/tls/tls.crt" "$integration/tls/tls.key" "$integration/results/local-integration-result.json" "$integration/results/admin-service.log" "$integration/results/integration.cover.out" "$integration/results/integration.coverage.txt"
rm -rf "$integration/results/go-coverage"
mkdir -p "$integration/results/go-coverage"
printf 'POSTGRES_SUPERUSER_PASSWORD=%s\n' "$(openssl rand -hex 24)" > "$integration/.env"
printf 'KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=local-admin\n' >> "$integration/.env"
printf 'KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)" >> "$integration/.env"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$integration/tls/tls.key" \
  -out "$integration/tls/tls.crt" \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  >/dev/null 2>&1
chmod 600 "$integration/.env" "$integration/tls/tls.key"
chmod +x "$integration/postgres-init/01-create-keycloak-db.sh"

"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
pkill -f '/tmp/go-build.*/exe/admin-service' >/dev/null 2>&1 || true
"${compose[@]}" up -d

for _ in $(seq 1 90); do
  if curl --silent --fail --cacert "$integration/tls/tls.crt" https://localhost:8443/realms/master/.well-known/openid-configuration >/dev/null; then
    break
  fi
  sleep 2
done
curl --silent --fail --cacert "$integration/tls/tls.crt" https://localhost:8443/realms/master/.well-known/openid-configuration >/dev/null || {
  "${compose[@]}" logs keycloak >&2
  exit 1
}

postgres_password="$(sed -n 's/^POSTGRES_SUPERUSER_PASSWORD=//p' "$integration/.env")"
keycloak_admin_password="$(sed -n 's/^KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=//p' "$integration/.env")"
ca=(--silent --show-error --fail --cacert "$integration/tls/tls.crt")
keycloak_base='https://localhost:8443'
realm='blueeconomy-integration'

master_token="$({ curl "${ca[@]}" -X POST "$keycloak_base/realms/master/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'client_id=admin-cli' \
  --data-urlencode 'username=local-admin' \
  --data-urlencode "password=$keycloak_admin_password"; } | jq -er '.access_token')"
admin_api="$keycloak_base/admin/realms"

curl "${ca[@]}" -o /dev/null -w '%{http_code}' -X POST "$admin_api" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg realm "$realm" '{realm:$realm,enabled:true}')" | grep -qx '201'

realm_document="$(curl "${ca[@]}" "$admin_api/$realm" -H "Authorization: Bearer $master_token")"
realm_with_smtp="$(jq '.organizationsEnabled=true | .smtpServer={host:"127.0.0.1",port:"1025",from:"integration@blueeconomy.local",auth:"false",starttls:"false",ssl:"false"}' <<<"$realm_document")"
curl "${ca[@]}" -o /dev/null -w '%{http_code}' -X PUT "$admin_api/$realm" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' --data "$realm_with_smtp" | grep -qx '204'

capture_location() {
  local headers status location
  headers="$(mktemp)"
  status="$(curl "${ca[@]}" -D "$headers" -o /dev/null -w '%{http_code}' "$@")"
  [[ "$status" == '201' ]] || { cat "$headers" >&2; rm -f "$headers"; return 1; }
  location="$(awk 'tolower($1)=="location:" {sub(/\r$/, "", $2); print $2}' "$headers" | tail -n 1)"
  rm -f "$headers"
  [[ -n "$location" ]] || return 1
  printf '%s' "${location##*/}"
}

organization_id="$(capture_location -X POST "$admin_api/$realm/organizations" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' \
  --data '{"name":"BlueEconomyLocalIntegrationOrganization","enabled":true}')"
group_id="$(capture_location -X POST "$admin_api/$realm/organizations/$organization_id/groups" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' \
  --data '{"name":"safety.telemetry.review"}')"

client_id='central-administration-local-service'
curl "${ca[@]}" -o /dev/null -w '%{http_code}' -X POST "$admin_api/$realm/clients" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg client_id "$client_id" '{clientId:$client_id,enabled:true,protocol:"openid-connect",publicClient:false,serviceAccountsEnabled:true,standardFlowEnabled:false,directAccessGrantsEnabled:false}')" | grep -qx '201'
client_uuid="$(curl "${ca[@]}" "$admin_api/$realm/clients?clientId=$client_id" -H "Authorization: Bearer $master_token" | jq -er '.[0].id')"
client_secret="$(curl "${ca[@]}" "$admin_api/$realm/clients/$client_uuid/client-secret" -H "Authorization: Bearer $master_token" | jq -er '.value')"
service_account_user="$(curl "${ca[@]}" "$admin_api/$realm/clients/$client_uuid/service-account-user" -H "Authorization: Bearer $master_token" | jq -er '.id')"
realm_management_uuid="$(curl "${ca[@]}" "$admin_api/$realm/clients?clientId=realm-management" -H "Authorization: Bearer $master_token" | jq -er '.[0].id')"
realm_admin_role="$(curl "${ca[@]}" "$admin_api/$realm/clients/$realm_management_uuid/roles/realm-admin" -H "Authorization: Bearer $master_token")"
curl "${ca[@]}" -o /dev/null -w '%{http_code}' -X POST "$admin_api/$realm/users/$service_account_user/role-mappings/clients/$realm_management_uuid" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' --data "[$realm_admin_role]" | grep -qx '204'

sudo docker compose --env-file "$integration/.env" -f "$integration/compose.yaml" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U platform -d adminservice < "$root/db/migrations/0001_onboarding.sql"
sudo docker compose --env-file "$integration/.env" -f "$integration/compose.yaml" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U platform -d adminservice < "$root/db/migrations/0002_activation.sql"

(cd "$root" && go build -cover -coverpkg=./... -o "$integration/results/admin-service-bin" ./cmd/admin-service)
ADMIN_SERVICE_LISTEN_ADDRESS='127.0.0.1:18080' \
ADMIN_SERVICE_POSTGRES_DSN="postgres://platform:$postgres_password@127.0.0.1:5432/adminservice?sslmode=disable" \
KEYCLOAK_TOKEN_URL="$keycloak_base/realms/$realm/protocol/openid-connect/token" \
KEYCLOAK_ADMIN_BASE_URL="$keycloak_base" \
KEYCLOAK_REALM="$realm" \
KEYCLOAK_ORGANIZATION_ID="$organization_id" \
KEYCLOAK_ADMIN_CLIENT_ID="$client_id" \
KEYCLOAK_ADMIN_CLIENT_SECRET="$client_secret" \
KEYCLOAK_CA_FILE="$integration/tls/tls.crt" \
KEYCLOAK_SERVICE_ACTOR_SUBJECT='service:central-administration-local-integration' \
GOCOVERDIR="$integration/results/go-coverage" \
ONBOARDING_ALLOWED_ROLES='safety.telemetry.review' \
KEYCLOAK_ROLE_GROUP_MAPPING_JSON="$(jq -nc --arg group "$group_id" '{"safety.telemetry.review":$group}')" \
"$integration/results/admin-service-bin" > "$integration/results/admin-service.log" 2>&1 &
service_pid="$!"

for _ in $(seq 1 30); do
  if curl --silent --fail http://127.0.0.1:18080/healthz >/dev/null; then break; fi
  sleep 1
done
curl --silent --fail http://127.0.0.1:18080/healthz >/dev/null
configured_organization="$(tr '\0' '\n' < "/proc/$service_pid/environ" | sed -n 's/^KEYCLOAK_ORGANIZATION_ID=//p')"
[[ "$configured_organization" == "$organization_id" ]] || {
  echo 'central administration service organization configuration mismatch' >&2
  exit 1
}

echo 'integration stage: verify API denials and input controls' >&2
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/v1/onboarding/requests -H 'Content-Type: application/json' --data '{}')" == '401' ]]
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/v1/onboarding/requests -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-requester' --data '{"undeclared":true}')" == '400' ]]
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/v1/onboarding/requests -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-requester' --data "$(jq -nc --arg org "$organization_id" '{organization_id:$org,email:"unsupported.role@blueeconomy.test",first_name:"Unsupported",last_name:"Role",requested_roles:["undeclared.role"]}')")" == '400' ]]

echo 'integration stage: submit onboarding request' >&2
submit_response="$(mktemp)"
submit_status="$(curl --silent --show-error -o "$submit_response" -w '%{http_code}' -X POST http://127.0.0.1:18080/v1/onboarding/requests \
  -H 'Content-Type: application/json' \
  -H 'X-Blueeconomy-Authenticated-Subject: local-requester' \
  --data "$(jq -nc --arg org "$organization_id" '{organization_id:$org,email:"stakeholder.local@blueeconomy.test",first_name:"Local",last_name:"Stakeholder",requested_roles:["safety.telemetry.review"]}')")"
if [[ "$submit_status" != '201' ]]; then
  cat "$submit_response" >&2
  rm -f "$submit_response"
  exit 1
fi
request_json="$(cat "$submit_response")"
rm -f "$submit_response"
request_id="$(jq -er '.id' <<<"$request_json")"
request_status="$(jq -er '.status' <<<"$request_json")"
[[ "$request_status" == 'submitted' ]]

echo 'integration stage: verify maker/checker and decision validation' >&2
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/decision" -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-requester' --data '{"decision":"approve","reason":"self approval must fail"}')" == '403' ]]
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/decision" -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-approver' --data '{"decision":"defer","reason":"unsupported"}')" == '400' ]]

echo 'integration stage: approve onboarding request' >&2
curl --silent --show-error --fail -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/decision" \
  -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-approver' \
  --data '{"decision":"approve","reason":"Local integration approval"}' | grep -qx '200'

echo 'integration stage: provision Keycloak invitation' >&2
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/provision")" == '401' ]]
curl --silent --show-error --fail -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/provision" \
  -H 'X-Blueeconomy-Authenticated-Subject: local-provisioner' | grep -qx '204'
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/provision" -H 'X-Blueeconomy-Authenticated-Subject: local-provisioner')" == '409' ]]

mail_count="$(curl --silent --show-error --fail http://127.0.0.1:8025/api/v1/messages | jq -er '.messages | length')"
[[ "$mail_count" -ge 1 ]]

user_id="$(capture_location -X POST "$admin_api/$realm/users" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' \
  --data '{"username":"local-stakeholder","email":"stakeholder.local@blueeconomy.test","firstName":"Local","lastName":"Stakeholder","enabled":true}')"
curl "${ca[@]}" -o /dev/null -w '%{http_code}' -X POST "$admin_api/$realm/organizations/$organization_id/members" \
  -H "Authorization: Bearer $master_token" -H 'Content-Type: application/json' --data "\"$user_id\"" | grep -qx '201'

echo 'integration stage: activate Keycloak organization group' >&2
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/activate" -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-activator' --data '{}')" == '400' ]]
curl --silent --show-error --fail -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/activate" \
  -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-activator' \
  --data "$(jq -nc --arg user_id "$user_id" '{keycloak_user_id:$user_id}')" | grep -qx '204'
[[ "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18080/v1/onboarding/requests/$request_id/activate" -H 'Content-Type: application/json' -H 'X-Blueeconomy-Authenticated-Subject: local-activator' --data "$(jq -nc --arg user_id "$user_id" '{keycloak_user_id:$user_id}')")" == '409' ]]

final_status="$(sudo docker compose --env-file "$integration/.env" -f "$integration/compose.yaml" exec -T postgres \
  psql -At -U platform -d adminservice -c "SELECT status FROM onboarding_requests WHERE id = '$request_id'" | tr -d '\r')"
[[ "$final_status" == 'active' ]]
decision_values="$(sudo docker compose --env-file "$integration/.env" -f "$integration/compose.yaml" exec -T postgres \
  psql -At -U platform -d adminservice -c "SELECT string_agg(decision, ',' ORDER BY created_at) FROM onboarding_decisions WHERE request_id = '$request_id'" | tr -d '\r')"
[[ "$decision_values" == 'approved,invited,active' ]]
group_members="$(curl "${ca[@]}" "$admin_api/$realm/organizations/$organization_id/groups/$group_id/members" -H "Authorization: Bearer $master_token")"
member_found="$(jq --arg user_id "$user_id" 'map(.id) | index($user_id) != null' <<<"$group_members")"
[[ "$member_found" == 'true' ]]

jq -n \
  --arg request_status "$request_status" \
  --arg final_status "$final_status" \
  --arg decisions "$decision_values" \
  --argjson mail_count "$mail_count" \
  --argjson group_member_found "$member_found" \
  '{request_status:$request_status,final_status:$final_status,decisions:$decisions,mail_count:$mail_count,keycloak_group_member_found:$group_member_found}' \
  > "$integration/results/local-integration-result.json"

cat "$integration/results/local-integration-result.json"

kill "$service_pid"
wait "$service_pid"
service_pid=""
(
  cd "$root"
  go tool covdata textfmt -i="$integration/results/go-coverage" -o="$integration/results/integration.cover.out"
  go tool cover -func="$integration/results/integration.cover.out" | tee "$integration/results/integration.coverage.txt"
)
