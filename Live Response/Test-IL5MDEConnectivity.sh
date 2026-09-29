#!/usr/bin/env bash
#
# Test Microsoft Defender for Endpoint outbound connectivity for Azure US
# Government DoD IL5 Linux devices.
#
# Live Response example:
#   run Test-IL5MDEConnectivity.sh
#
# The script is read only. It creates a diagnostic archive under /tmp and
# prints the exact getfile command needed to retrieve it.

set -u
set -o pipefail
umask 077

SCRIPT_VERSION="1.0.0"
CONNECT_TIMEOUT=10
MAX_TIME=20
FAILURES=0
WARNINGS=0

MDE_DOC="https://learn.microsoft.com/defender-endpoint/streamlined-device-connectivity-urls-gov"

HOST_NAME="$(hostname 2>/dev/null || printf 'unknown-host')"
SAFE_HOST="$(printf '%s' "$HOST_NAME" | tr -cs 'A-Za-z0-9._-' '_')"
UTC_STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
BUNDLE_NAME="IL5MDEConnectivity_${SAFE_HOST}_${UTC_STAMP}"
WORK_DIR="/tmp/${BUNDLE_NAME}"
ARCHIVE_PATH="/tmp/${BUNDLE_NAME}.tar.gz"
SUMMARY_FILE="${WORK_DIR}/summary.txt"
CSV_FILE="${WORK_DIR}/endpoint-results.csv"
TLS_FILE="${WORK_DIR}/tls-certificates.txt"
HTML_ROWS_FILE="${WORK_DIR}/endpoint-rows.html"
REPORT_FILE="${WORK_DIR}/IL5-MDE-Connectivity-Report.html"

mkdir -p "$WORK_DIR" || {
    printf 'ERROR: Unable to create %s\n' "$WORK_DIR" >&2
    exit 1
}

cleanup_on_signal() {
    printf 'ERROR: Test interrupted. Partial files remain at %s\n' "$WORK_DIR" >&2
    exit 2
}

trap cleanup_on_signal HUP INT TERM

csv_quote() {
    printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"
}

html_escape_text() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g'
}

html_escape_file() {
    local file="$1"
    if [ -r "$file" ]; then
        sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$file"
    else
        printf 'Not collected.'
    fi
}

append_html_cell() {
    printf '<td>'
    html_escape_text "$1"
    printf '</td>'
}

append_result() {
    local service="$1"
    local requirement="$2"
    local host="$3"
    local port="$4"
    local dns_result="$5"
    local tcp_result="$6"
    local http_result="$7"
    local http_code="$8"
    local remote_ip="$9"
    local total_time="${10}"
    local tls_verify="${11}"
    local detail="${12}"

    {
        csv_quote "$service"; printf ','
        csv_quote "$requirement"; printf ','
        csv_quote "$host"; printf ','
        csv_quote "$port"; printf ','
        csv_quote "$dns_result"; printf ','
        csv_quote "$tcp_result"; printf ','
        csv_quote "$http_result"; printf ','
        csv_quote "$http_code"; printf ','
        csv_quote "$remote_ip"; printf ','
        csv_quote "$total_time"; printf ','
        csv_quote "$tls_verify"; printf ','
        csv_quote "$detail"; printf '\n'
    } >>"$CSV_FILE"

    {
        printf '<tr>'
        append_html_cell "$service"
        append_html_cell "$requirement"
        append_html_cell "$host"
        append_html_cell "$port"
        append_html_cell "$dns_result"
        append_html_cell "$tcp_result"
        append_html_cell "$http_result"
        append_html_cell "$http_code"
        append_html_cell "$remote_ip"
        append_html_cell "$total_time"
        append_html_cell "$tls_verify"
        append_html_cell "$detail"
        printf '</tr>\n'
    } >>"$HTML_ROWS_FILE"
}

record_failure() {
    FAILURES=$((FAILURES + 1))
    printf 'FAIL: %s\n' "$1" | tee -a "$SUMMARY_FILE" >&2
}

record_warning() {
    WARNINGS=$((WARNINGS + 1))
    printf 'WARNING: %s\n' "$1" | tee -a "$SUMMARY_FILE" >&2
}

resolve_host() {
    local host="$1"
    local addresses=""

    if command -v getent >/dev/null 2>&1; then
        addresses="$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd ';' -)"
    elif command -v host >/dev/null 2>&1; then
        addresses="$(host "$host" 2>/dev/null | awk '/has address/ {print $4}' | sort -u | paste -sd ';' -)"
    elif command -v nslookup >/dev/null 2>&1; then
        addresses="$(nslookup "$host" 2>/dev/null | awk '/^Address: / {print $2}' | sort -u | paste -sd ';' -)"
    fi

    if [ -n "$addresses" ]; then
        printf '%s' "$addresses"
    else
        printf 'UNRESOLVED'
    fi
}

test_tcp() {
    local host="$1"
    local port="$2"

    if command -v timeout >/dev/null 2>&1; then
        if timeout "$CONNECT_TIMEOUT" bash -c "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1; then
            printf 'PASS'
        else
            printf 'FAIL'
        fi
    else
        printf 'NOT TESTED: timeout unavailable'
    fi
}

collect_tls_certificate() {
    local service="$1"
    local host="$2"
    local port="$3"

    [ "$port" = "443" ] || return 0
    command -v openssl >/dev/null 2>&1 || return 0
    command -v timeout >/dev/null 2>&1 || return 0

    {
        printf '\n=== %s: %s:%s ===\n' "$service" "$host" "$port"
        timeout "$MAX_TIME" openssl s_client -connect "${host}:${port}" \
            -servername "$host" -showcerts </dev/null 2>/dev/null \
            | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1
    } >>"$TLS_FILE"
}

test_endpoint() {
    local service="$1"
    local requirement="$2"
    local url="$3"
    local host="$4"
    local port="$5"
    local dns_result tcp_result curl_output curl_error curl_rc
    local http_code="000"
    local remote_ip=""
    local total_time=""
    local tls_verify=""
    local http_result="NOT TESTED"
    local detail=""
    local endpoint_reachable=0
    local error_file="${WORK_DIR}/curl-error-${host//[^A-Za-z0-9]/_}-${port}.txt"
    local -a curl_tls_args=()

    dns_result="$(resolve_host "$host")"
    tcp_result="$(test_tcp "$host" "$port")"

    if command -v curl >/dev/null 2>&1; then
        if [ "$port" = "443" ]; then
            curl_tls_args=(--tlsv1.2)
        fi
        curl_output="$(curl --silent --show-error --head \
            --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
            "${curl_tls_args[@]}" \
            --output /dev/null \
            --write-out '%{http_code}|%{remote_ip}|%{time_total}|%{ssl_verify_result}' \
            "$url" 2>"$error_file")"
        curl_rc=$?

        IFS='|' read -r http_code remote_ip total_time tls_verify <<EOF
$curl_output
EOF

        if [ "$curl_rc" -ne 0 ] || [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
            http_result="FAIL"
            detail="$(tr '\r\n' '  ' <"$error_file" | cut -c1-500)"
        elif [ "$http_code" = "407" ]; then
            http_result="FAIL"
            detail="Proxy authentication required."
        elif [ "$http_code" -ge 500 ] 2>/dev/null; then
            http_result="WARN: REACHABLE"
            detail="TLS and HTTP transport succeeded, but the service or gateway returned HTTP ${http_code}."
            endpoint_reachable=1
        elif [ "$http_code" -ge 400 ] 2>/dev/null; then
            http_result="PASS: REACHABLE"
            detail="Anonymous request was rejected with HTTP ${http_code}; network path succeeded."
            endpoint_reachable=1
        else
            http_result="PASS"
            detail="HTTP ${http_code}."
            endpoint_reachable=1
        fi
    else
        curl_rc=127
        http_result="NOT TESTED"
        detail="curl is not installed."
    fi

    append_result "$service" "$requirement" "$host" "$port" "$dns_result" \
        "$tcp_result" "$http_result" "$http_code" "$remote_ip" "$total_time" \
        "$tls_verify" "$detail"
    collect_tls_certificate "$service" "$host" "$port"

    if [ "$requirement" = "Required" ] && [ "$endpoint_reachable" -eq 0 ]; then
        record_failure "${service} (${host}:${port}) did not pass the HTTP test."
    elif [ "$endpoint_reachable" -eq 1 ] && [ "${http_result%%:*}" = "WARN" ]; then
        record_warning "${service} (${host}:${port}) is reachable but returned HTTP ${http_code}."
    elif [ "$requirement" != "Required" ] && [ "$endpoint_reachable" -eq 0 ]; then
        record_warning "${service} (${host}:${port}) did not pass its conditional test."
    fi
}

run_logged() {
    local label="$1"
    local output_file="$2"
    local seconds="$3"
    shift 3

    {
        printf 'Check: %s\n' "$label"
        printf 'UTC: %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        if command -v timeout >/dev/null 2>&1; then
            timeout "$seconds" "$@"
        else
            "$@"
        fi
    } >"$output_file" 2>&1

    return $?
}

{
    printf 'IL5 Microsoft Defender for Endpoint connectivity analysis\n'
    printf 'Script version: %s\n' "$SCRIPT_VERSION"
    printf 'Device: %s\n' "$HOST_NAME"
    printf 'UTC started: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'MDE endpoint source: %s\n' "$MDE_DOC"
    printf '\nThis script is read only and sends anonymous connectivity probes only.\n'
    printf 'Any HTTP response except proxy authentication or server errors proves reachability.\n'
    printf 'A working Live Response session confirms its current control channel is reachable.\n\n'
} >"$SUMMARY_FILE"

printf '"Service","Requirement","Host","Port","DNS","DirectTCP","HTTP","HTTPCode","RemoteIP","Seconds","TLSVerify","Detail"\n' >"$CSV_FILE"
: >"$HTML_ROWS_FILE"
printf 'TLS certificate details. Review issuer names for unexpected inspection devices.\n' >"$TLS_FILE"

# Required MDE DoD endpoints with concrete hostnames.
test_endpoint "MDE SmartScreen DoD" "Required" \
    "https://unitedstates2.ss.wd.microsoft.us/" "unitedstates2.ss.wd.microsoft.us" "443"
test_endpoint "MDE internal configuration DoD" "Required" \
    "https://config.ecs.dod.teams.microsoft.us/config/v1" "config.ecs.dod.teams.microsoft.us" "443"
test_endpoint "MDE government identity" "Required" \
    "https://login.microsoftonline.us/" "login.microsoftonline.us" "443"
test_endpoint "MDE Live Response identity" "Required" \
    "https://login.live.com/" "login.live.com" "443"
test_endpoint "MDE certificate revocation" "Required" \
    "http://crl.microsoft.com/pki/crl/" "crl.microsoft.com" "80"
test_endpoint "MDE certificate operations" "Required" \
    "http://www.microsoft.com/pkiops/" "www.microsoft.com" "80"
test_endpoint "MDE certificate download" "Required" \
    "http://www.microsoft.com/pki/certs" "www.microsoft.com" "80"

cat >"${WORK_DIR}/wildcard-endpoints.txt" <<'EOF'
Wildcard endpoints cannot be tested as literal DNS names.
The native mdatp connectivity test discovers and tests the concrete tenant
service endpoints used by the installed Defender agent.

Required MDE US Government:
  *.endpoint.security.microsoft.us:443
  *.wns.windows.com:443
EOF

if command -v mdatp >/dev/null 2>&1; then
    if ! run_logged "MDE version" "${WORK_DIR}/mdatp-version.txt" 60 \
        sh -c 'mdatp health --field app_version 2>/dev/null || mdatp version'; then
        record_warning "The installed MDE version could not be read."
    fi

    if run_logged "MDE health" "${WORK_DIR}/mdatp-health.txt" 90 mdatp health; then
        if grep -Eqi '^[[:space:]]*(healthy|licensed|cloud_enabled)[[:space:]]*:[[:space:]]*false' \
            "${WORK_DIR}/mdatp-health.txt"; then
            record_failure "MDE reports an unhealthy, unlicensed, or disabled cloud state."
        else
            printf 'PASS: mdatp health completed without a critical false state.\n' >>"$SUMMARY_FILE"
        fi
    else
        record_failure "mdatp health failed; review mdatp-health.txt."
    fi

    if run_logged "MDE government connectivity" "${WORK_DIR}/mdatp-connectivity.txt" \
        240 mdatp connectivity test; then
        if grep -Eqi '\[(FAIL|FAILED)\]' "${WORK_DIR}/mdatp-connectivity.txt"; then
            record_failure "mdatp connectivity test reported a failed endpoint."
        else
            printf 'PASS: mdatp connectivity test completed successfully.\n' >>"$SUMMARY_FILE"
        fi
    else
        record_failure "mdatp connectivity test failed; review mdatp-connectivity.txt."
    fi
else
    record_failure "mdatp is not installed or is not available in PATH."
fi

if command -v systemctl >/dev/null 2>&1; then
    if ! run_logged "MDE service status" "${WORK_DIR}/mdatp-service.txt" 60 \
        systemctl status mdatp --no-pager; then
        record_failure "The mdatp service is not active; review mdatp-service.txt."
    fi
fi

if command -v journalctl >/dev/null 2>&1; then
    run_logged "MDE service journal" "${WORK_DIR}/mdatp-journal.txt" 90 \
        journalctl -u mdatp --since "24 hours ago" --no-pager --utc
fi

{
    printf 'System\n'
    uname -a 2>/dev/null || true
    printf '\nOperating system\n'
    cat /etc/os-release 2>/dev/null || true
    printf '\nRoutes\n'
    ip route show table all 2>/dev/null || route -n 2>/dev/null || true
    printf '\nDNS\n'
    resolvectl status 2>/dev/null || cat /etc/resolv.conf 2>/dev/null || true
    printf '\nClock and synchronization\n'
    date -u 2>/dev/null || true
    timedatectl status 2>/dev/null || true
    printf '\nTLS library\n'
    openssl version -a 2>/dev/null || true
    printf '\nFIPS mode\n'
    cat /proc/sys/crypto/fips_enabled 2>/dev/null || printf 'Not reported\n'
    printf '\nProxy variable presence\n'
    for proxy_name in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY; do
        if printenv "$proxy_name" >/dev/null 2>&1; then
            printf '%s: SET (value redacted)\n' "$proxy_name"
        else
            printf '%s: not set\n' "$proxy_name"
        fi
    done
} >"${WORK_DIR}/system-network.txt"

{
    printf 'Local outbound firewall rules, bounded to 2000 lines per source\n\n'
    if command -v nft >/dev/null 2>&1; then
        printf '=== nftables ===\n'
        nft list ruleset 2>&1 | head -n 2000
    fi
    if command -v iptables-save >/dev/null 2>&1; then
        printf '\n=== iptables ===\n'
        iptables-save 2>&1 | head -n 2000
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        printf '\n=== firewalld ===\n'
        firewall-cmd --state 2>&1
        firewall-cmd --list-all 2>&1
    fi
} >"${WORK_DIR}/local-firewall.txt"

{
    printf '\nRequired failures: %s\n' "$FAILURES"
    printf 'Conditional warnings: %s\n' "$WARNINGS"
    printf 'UTC completed: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if [ "$FAILURES" -eq 0 ]; then
        printf 'Overall result: PASS\n'
    else
        printf 'Overall result: FAIL\n'
    fi
} >>"$SUMMARY_FILE"

if [ "$FAILURES" -eq 0 ]; then
    OVERALL_RESULT="PASS"
    RESULT_CLASS="pass"
else
    OVERALL_RESULT="FAIL"
    RESULT_CLASS="fail"
fi

cat >"$REPORT_FILE" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IL5 MDE Connectivity Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; background: #f8fafc; }
h1, h2 { color: #0f172a; }
.card { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
.pass { color: #166534; font-weight: bold; }
.fail { color: #b91c1c; font-weight: bold; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td { border: 1px solid #cbd5e1; padding: 0.4rem; text-align: left; vertical-align: top; }
th { background: #e2e8f0; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 6px; max-height: 32rem; overflow: auto; }
details { margin-bottom: 0.75rem; }
summary { cursor: pointer; font-weight: bold; padding: 0.5rem; }
</style>
</head>
<body>
<h1>IL5 Microsoft Defender for Endpoint Connectivity Report</h1>
<div class="card">
<p><strong>Device:</strong> $(html_escape_text "$HOST_NAME")</p>
<p><strong>Completed UTC:</strong> $(date -u '+%Y-%m-%dT%H:%M:%SZ')</p>
<p><strong>Overall result:</strong> <span class="$RESULT_CLASS">$OVERALL_RESULT</span></p>
<p><strong>Required failures:</strong> $FAILURES</p>
<p><strong>Warnings:</strong> $WARNINGS</p>
<p><strong>Microsoft source:</strong> <a href="$MDE_DOC">$MDE_DOC</a></p>
</div>
<div class="card">
<h2>Endpoint results</h2>
<table>
<thead><tr><th>Service</th><th>Requirement</th><th>Host</th><th>Port</th><th>DNS</th><th>Direct TCP</th><th>HTTP</th><th>Code</th><th>Remote IP</th><th>Seconds</th><th>TLS verify</th><th>Detail</th></tr></thead>
<tbody>
$(cat "$HTML_ROWS_FILE")
</tbody>
</table>
</div>
<div class="card">
<h2>Detailed evidence</h2>
<details open><summary>Summary</summary><pre>$(html_escape_file "$SUMMARY_FILE")</pre></details>
<details open><summary>MDE connectivity test</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-connectivity.txt")</pre></details>
<details><summary>MDE health</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-health.txt")</pre></details>
<details><summary>MDE version</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-version.txt")</pre></details>
<details><summary>MDE service</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-service.txt")</pre></details>
<details><summary>MDE journal, previous 24 hours</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-journal.txt")</pre></details>
<details><summary>TLS certificates</summary><pre>$(html_escape_file "$TLS_FILE")</pre></details>
<details><summary>System, network, clock, FIPS, and proxy evidence</summary><pre>$(html_escape_file "${WORK_DIR}/system-network.txt")</pre></details>
<details><summary>Local firewall rules</summary><pre>$(html_escape_file "${WORK_DIR}/local-firewall.txt")</pre></details>
<details><summary>Wildcard endpoint notes</summary><pre>$(html_escape_file "${WORK_DIR}/wildcard-endpoints.txt")</pre></details>
</div>
</body>
</html>
EOF

if ! tar -czf "$ARCHIVE_PATH" -C /tmp "$BUNDLE_NAME"; then
    printf 'ERROR: Unable to create archive. Partial files remain at %s\n' "$WORK_DIR" >&2
    exit 3
fi

if [ ! -s "$ARCHIVE_PATH" ]; then
    printf 'ERROR: Archive is empty: %s\n' "$ARCHIVE_PATH" >&2
    exit 4
fi

rm -rf -- "$WORK_DIR"

printf 'Device: %s\n' "$HOST_NAME"
printf 'UTC: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'Required failures: %s\n' "$FAILURES"
printf 'Conditional warnings: %s\n' "$WARNINGS"
printf 'Saved: %s\n' "$ARCHIVE_PATH"
printf 'Retrieve with: getfile "%s"\n' "$ARCHIVE_PATH"

if [ "$FAILURES" -gt 0 ]; then
    exit 10
fi
exit 0
