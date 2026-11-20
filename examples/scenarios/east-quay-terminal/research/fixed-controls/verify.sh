#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJECT="eastquay-fixed-controls-$$"
TMP="$(mktemp -d /tmp/eastquay-fixed-controls.XXXXXX)"
FIXED_STAFF_HASH='$2y$10$FyLQaUtr0b/nI6or1m1mpue3ZlHo3ih37JuP5l3IyKG.M92f9NB3S'
REUSED_STAFF_HASH='$2y$10$zx0Q/8pOUDH443QShwO.QutKsz041WPA4V05XT2kn0aw0qZ5agXHa'

dc() {
  docker compose --project-name "$PROJECT" -f "$HERE/compose.yaml" "$@"
}

cleanup() {
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

dc up --build --wait --detach
TARGET="$(dc exec -T port-db cat /var/lib/mysql/.east-quay-target-id | tr -d '\r\n')"
[[ "$TARGET" =~ ^[0-9]{6}$ ]]
dc exec -T port-db mariadb -uroot -plocal-root-only eastquay -e \
  "UPDATE port_staff SET Password_Hash='${REUSED_STAFF_HASH}' WHERE Staff_Id=9001"
VULN_PORT="$(dc port port-app-vulnerable 80 | sed 's/.*://')"
FIXED_PORT="$(dc port port-app-fixed 80 | sed 's/.*://')"
VULN_URL="http://127.0.0.1:${VULN_PORT}"
FIXED_URL="http://127.0.0.1:${FIXED_PORT}"

VULN_LIST="$(curl -fsS "${VULN_URL}/request_table.php")"
grep -Fq "$TARGET" <<<"$VULN_LIST"
FIXED_LIST_CODE="$(curl -sS -o "$TMP/fixed-list.html" -w '%{http_code}' \
  "${FIXED_URL}/request_table.php")"
test "$FIXED_LIST_CODE" = 403

curl -fsS -c "$TMP/carrier-vuln.cookie" -o /dev/null \
  -d 'user_id=1001&email=agent%40northshore.example&password=password' \
  "${VULN_URL}/authenticate.php"
curl -fsS -c "$TMP/carrier-fixed.cookie" -o /dev/null \
  -d 'user_id=1001&email=agent%40northshore.example&password=password' \
  "${FIXED_URL}/authenticate.php"

SQLI_PAYLOAD="0' UNION SELECT 'AL',CONCAT(Staff_Id,':',Email,':',Password_Hash) FROM port_staff -- "
VULN_SQLI="$(curl -fsS -b "$TMP/carrier-vuln.cookie" \
  --data-urlencode "shipnumber=$SQLI_PAYLOAD" \
  "${VULN_URL}/shipstatus_cntry.php")"
grep -Fq '9001:ops@eastquay.example:' <<<"$VULN_SQLI"
FIXED_SQLI_CODE="$(curl -sS -b "$TMP/carrier-fixed.cookie" -o "$TMP/fixed-sqli.html" \
  -w '%{http_code}' --data-urlencode "shipnumber=$SQLI_PAYLOAD" \
  "${FIXED_URL}/shipstatus_cntry.php")"
test "$FIXED_SQLI_CODE" = 400
! grep -Fq 'ops@eastquay.example' "$TMP/fixed-sqli.html"

curl -fsS -c "$TMP/ops-vuln.cookie" -o /dev/null \
  -d 'user_id=9001&email=ops%40eastquay.example&password=password' \
  "${VULN_URL}/adminlogin.php"
VULN_OPS_CODE="$(curl -sS -b "$TMP/ops-vuln.cookie" -o /dev/null \
  -w '%{http_code}' "${VULN_URL}/adminHome.php")"
test "$VULN_OPS_CODE" = 200

curl -fsS -b "$TMP/ops-vuln.cookie" -o /dev/null \
  -d "countryid=1&shipnumber=${TARGET}&curr_status=PL" \
  "${VULN_URL}/shipstatus.php"
VULN_STATE="$(dc exec -T port-db mariadb -ueastquay -plocal-only eastquay -N -e \
  "SELECT CONCAT(s.Curr_Status,'|',c.Status,'|',(SELECT COUNT(*) FROM yard_events e WHERE e.Ship_Number=s.Number)) FROM ships s JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id WHERE s.Number=${TARGET} AND s.Id=1" | tr -d '\r')"
test "$VULN_STATE" = 'PL|On Hold|0'

# Restore the pre-incident state and model the corrected, non-reused staff secret.
dc exec -T port-db mariadb -ueastquay -plocal-only eastquay -e \
  "UPDATE ships SET Curr_Status='AL' WHERE Number=${TARGET} AND Id=1"
dc exec -T port-db mariadb -uroot -plocal-root-only eastquay -e \
  "UPDATE port_staff SET Password_Hash='${FIXED_STAFF_HASH}' WHERE Staff_Id=9001"

FIXED_REUSE_BODY="$(curl -sS -c "$TMP/ops-reuse-fixed.cookie" \
  -d 'user_id=9001&email=ops%40eastquay.example&password=password' \
  "${FIXED_URL}/adminlogin.php")"
grep -Fq 'Invalid credentials' <<<"$FIXED_REUSE_BODY"
FIXED_OPS_CODE="$(curl -sS -b "$TMP/ops-reuse-fixed.cookie" -o /dev/null \
  -w '%{http_code}' "${FIXED_URL}/adminHome.php")"
test "$FIXED_OPS_CODE" = 403

curl -fsS -c "$TMP/ops-fixed.cookie" -o /dev/null \
  -d 'user_id=9001&email=ops%40eastquay.example&password=QuayOps%21Runbook-8Vessel' \
  "${FIXED_URL}/adminlogin.php"
FIXED_DIRECT_CODE="$(curl -sS -b "$TMP/ops-fixed.cookie" -o /dev/null \
  -w '%{http_code}' -d "countryid=1&shipnumber=${TARGET}&curr_status=PL" \
  "${FIXED_URL}/shipstatus.php")"
test "$FIXED_DIRECT_CODE" = 409
FIXED_STATE="$(dc exec -T port-db mariadb -ueastquay -plocal-only eastquay -N -e \
  "SELECT CONCAT(s.Curr_Status,'|',c.Status,'|',(SELECT COUNT(*) FROM yard_events e WHERE e.Ship_Number=s.Number)) FROM ships s JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id WHERE s.Number=${TARGET} AND s.Id=1" | tr -d '\r')"
test "$FIXED_STATE" = 'AL|On Hold|0'

echo "East Quay deployed-weakness fixed-control A/B: PASS"
