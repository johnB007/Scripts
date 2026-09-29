#!/usr/bin/env bash
#
# Collect read only Microsoft Defender for Endpoint diagnostics on Linux.
# Upload this file to the Live Response library, then run:
#   run Collect-MDELinuxDiagnostics.sh
# Use the printed getfile command to retrieve the resulting archive.

set -u
set -o pipefail
umask 077

SCRIPT_VERSION="1.0.0"
SUPPORT_MATRIX_DATE="2026-09-28"
SUPPORT_DOC="https://learn.microsoft.com/defender-endpoint/mde-linux-prerequisites#supported-linux-distributions"
CONNECTIVITY_DOC="https://learn.microsoft.com/defender-endpoint/linux-support-connectivity"
ANALYZER_DOC="https://learn.microsoft.com/defender-endpoint/run-analyzer-linux"

HOST_NAME="$(hostname 2>/dev/null || printf 'unknown-host')"
SAFE_HOST="$(printf '%s' "$HOST_NAME" | tr -cs 'A-Za-z0-9._-' '_')"
UTC_STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
BUNDLE_NAME="MDELinuxDiagnostics_${SAFE_HOST}_${UTC_STAMP}"
WORK_DIR="/tmp/${BUNDLE_NAME}"
ARCHIVE_PATH="/tmp/${BUNDLE_NAME}.tar.gz"
SUMMARY_FILE="${WORK_DIR}/summary.txt"
REPORT_FILE="${WORK_DIR}/MDE-Linux-Diagnostics-Report.html"
ERROR_COUNT=0

mkdir -p "$WORK_DIR" || {
    printf 'ERROR: Unable to create %s\n' "$WORK_DIR" >&2
    exit 1
}

cleanup_on_signal() {
    printf 'ERROR: Collection interrupted. Partial files remain at %s\n' "$WORK_DIR" >&2
    exit 2
}

trap cleanup_on_signal HUP INT TERM

record_error() {
    ERROR_COUNT=$((ERROR_COUNT + 1))
    printf 'WARNING: %s\n' "$1" | tee -a "$SUMMARY_FILE" >&2
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

run_capture() {
    local label="$1"
    local output_file="$2"
    shift 2

    {
        printf 'Collection: %s\n' "$label"
        printf 'UTC: %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        "$@"
    } >"$output_file" 2>&1

    local result=$?
    if [ "$result" -ne 0 ]; then
        record_error "${label} returned exit code ${result}; see $(basename "$output_file")."
    fi
    return 0
}

run_bounded_capture() {
    local seconds="$1"
    local label="$2"
    local output_file="$3"
    shift 3

    if command -v timeout >/dev/null 2>&1; then
        run_capture "$label" "$output_file" timeout "$seconds" "$@"
    else
        run_capture "$label" "$output_file" "$@"
    fi
}

version_at_least() {
    local actual="$1"
    local minimum="$2"
    local actual_major actual_minor minimum_major minimum_minor

    actual_major="$(printf '%s' "$actual" | cut -d. -f1 | tr -cd '0-9')"
    actual_minor="$(printf '%s' "$actual" | cut -d. -f2 | tr -cd '0-9')"
    minimum_major="$(printf '%s' "$minimum" | cut -d. -f1 | tr -cd '0-9')"
    minimum_minor="$(printf '%s' "$minimum" | cut -d. -f2 | tr -cd '0-9')"

    [ -n "$actual_major" ] || return 1
    [ -n "$actual_minor" ] || actual_minor=0
    [ -n "$minimum_major" ] || return 1
    [ -n "$minimum_minor" ] || minimum_minor=0

    if [ "$actual_major" -gt "$minimum_major" ]; then
        return 0
    fi
    [ "$actual_major" -eq "$minimum_major" ] && [ "$actual_minor" -ge "$minimum_minor" ]
}

is_one_of() {
    local value="$1"
    shift
    local item
    for item in "$@"; do
        [ "$value" = "$item" ] && return 0
    done
    return 1
}

assess_support() {
    local distro_id="$1"
    local distro_version="$2"
    local architecture="$3"
    local major

    major="$(printf '%s' "$distro_version" | cut -d. -f1)"
    case "$architecture" in
        x86_64|amd64)
            case "$distro_id" in
                rhel|centos|ol)
                    if [ "$major" = "7" ]; then
                        version_at_least "$distro_version" "7.2" && printf 'SUPPORTED' || printf 'UNSUPPORTED'
                    elif is_one_of "$major" 8 9 10; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi
                    ;;
                centos-stream) is_one_of "$major" 8 9 10 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                ubuntu) is_one_of "$distro_version" 16.04 18.04 20.04 22.04 24.04 26.04 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                debian) [ "$major" -ge 9 ] 2>/dev/null && [ "$major" -le 13 ] 2>/dev/null && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                sles) is_one_of "$major" 12 15 16 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                opensuse-leap) if [ "$distro_version" = 15.6 ] || [ "$major" = 16 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                amzn) is_one_of "$distro_version" 2 2023 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                fedora) [ "$major" -ge 33 ] 2>/dev/null && [ "$major" -le 44 ] 2>/dev/null && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                rocky) if is_one_of "$major" 8 9; then version_at_least "$distro_version" "${major}.$([ "$major" = 8 ] && printf 7 || printf 2)" && printf 'SUPPORTED' || printf 'UNSUPPORTED'; elif [ "$major" = 10 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                almalinux) if is_one_of "$major" 8 9; then version_at_least "$distro_version" "${major}.$([ "$major" = 8 ] && printf 4 || printf 2)" && printf 'SUPPORTED' || printf 'UNSUPPORTED'; elif [ "$major" = 10 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                mariner) [ "$major" = 2 ] && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                *) printf 'MANUAL REVIEW' ;;
            esac
            ;;
        aarch64|arm64)
            case "$distro_id" in
                rhel|ol|centos-stream) is_one_of "$major" 8 9 10 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                ubuntu) is_one_of "$distro_version" 20.04 22.04 24.04 26.04 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                debian) is_one_of "$major" 11 12 13 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                sles) if [ "$major" = 16 ]; then printf 'SUPPORTED'; elif [ "$distro_version" = 15.5 ] || [ "$distro_version" = 15.6 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                opensuse-leap) if [ "$distro_version" = 15.6 ] || [ "$major" = 16 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                amzn) is_one_of "$distro_version" 2 2023 && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                fedora) [ "$major" -ge 40 ] 2>/dev/null && [ "$major" -le 44 ] 2>/dev/null && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                rocky) if is_one_of "$major" 8 9; then version_at_least "$distro_version" "${major}.$([ "$major" = 8 ] && printf 7 || printf 2)" && printf 'SUPPORTED' || printf 'UNSUPPORTED'; elif [ "$major" = 10 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                almalinux) if is_one_of "$major" 8 9; then version_at_least "$distro_version" "${major}.$([ "$major" = 8 ] && printf 4 || printf 2)" && printf 'SUPPORTED' || printf 'UNSUPPORTED'; elif [ "$major" = 10 ]; then printf 'SUPPORTED'; else printf 'UNSUPPORTED'; fi ;;
                mariner) [ "$major" = 2 ] && printf 'SUPPORTED' || printf 'UNSUPPORTED' ;;
                *) printf 'MANUAL REVIEW' ;;
            esac
            ;;
        *) printf 'MANUAL REVIEW' ;;
    esac
}

OS_ID="unknown"
OS_VERSION="unknown"
OS_PRETTY_NAME="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_PRETTY_NAME="${PRETTY_NAME:-unknown}"
    case "$OS_PRETTY_NAME" in
        *"CentOS Stream"*) OS_ID="centos-stream" ;;
    esac
fi
ARCHITECTURE="$(uname -m 2>/dev/null || printf 'unknown')"
KERNEL_VERSION="$(uname -r 2>/dev/null || printf 'unknown')"
SUPPORT_ASSESSMENT="$(assess_support "$OS_ID" "$OS_VERSION" "$ARCHITECTURE")"

{
    printf 'MDE Linux Live Response diagnostic collection\n'
    printf 'Script version: %s\n' "$SCRIPT_VERSION"
    printf 'Device: %s\n' "$HOST_NAME"
    printf 'UTC started: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'Run as: %s (UID %s)\n' "$(id -un 2>/dev/null || printf 'unknown')" "$(id -u 2>/dev/null || printf 'unknown')"
    printf 'Operating system: %s\n' "$OS_PRETTY_NAME"
    printf 'Distribution ID: %s\n' "$OS_ID"
    printf 'Distribution version: %s\n' "$OS_VERSION"
    printf 'Architecture: %s\n' "$ARCHITECTURE"
    printf 'Kernel: %s\n' "$KERNEL_VERSION"
    printf 'Support assessment: %s\n' "$SUPPORT_ASSESSMENT"
    printf 'Support matrix snapshot date: %s\n' "$SUPPORT_MATRIX_DATE"
    printf 'Current support source: %s\n' "$SUPPORT_DOC"
    printf 'Connectivity source: %s\n' "$CONNECTIVITY_DOC"
    printf 'Client Analyzer source: %s\n' "$ANALYZER_DOC"
    printf '\nThis script makes no configuration changes and performs no remediation.\n'
    printf 'It creates diagnostic files only under /tmp.\n'
} >"$SUMMARY_FILE"

cat >"${WORK_DIR}/supported-linux-versions.txt" <<'EOF'
Microsoft Defender for Endpoint supported Linux distributions
Snapshot date: 2026-09-28
Always verify the current matrix:
https://learn.microsoft.com/defender-endpoint/mde-linux-prerequisites#supported-linux-distributions

Distribution                       x64                         ARM64
Red Hat Enterprise Linux           7.2+, 8.x, 9.x, 10.x       8.x, 9.x, 10.x
CentOS                              7.2+, 8.x                   Not supported
CentOS Stream                       8.x, 9.x, 10.x              8.x, 9.x, 10.x
Ubuntu LTS                          16.04, 18.04, 20.04,        20.04, 22.04, 24.04,
                                    22.04, 24.04, 26.04         26.04
Ubuntu Pro                          22.04, 24.04                22.04, 24.04
Debian                              9 through 13                11, 12, 13
SUSE Linux Enterprise Server       12.x, 15.x, 16.x           15 SP5 or SP6, 16.x
openSUSE Leap                       15.6, 16.x                  15.6, 16.x
Oracle Linux                        7.2+, 8.x, 9.x, 10.x       8.x, 9.x, 10.x
Amazon Linux                        2, 2023                     2, 2023
Fedora                              33 through 44               40 through 44
Rocky Linux                         8.7+, 9.2+, 10.x           8.7+, 9.2+, 10.x
Alma Linux                          8.4+, 9.2+, 10.x           8.4+, 9.2+, 10.x
Mariner                             2                           2

Minimum kernel for supported distributions: 3.10.0-327 or later.
Linux Live Response requires MDE agent version 101.45.13 or later.
The Client Analyzer is included with MDE agent version 101.25082.0000 or later.
Amazon Linux 2 on ARM64 support retires on 2026-10-31. Its last supported
Defender version is 101.25122.0004.
Customized distributions are outside Microsoft's validated support baseline.
EOF

run_capture "System identity" "${WORK_DIR}/system.txt" sh -c '
    uname -a
    printf "\n/etc/os-release\n"
    cat /etc/os-release 2>/dev/null || true
    printf "\nUptime\n"
    uptime 2>/dev/null || true
    printf "\nCPU\n"
    nproc 2>/dev/null || true
    printf "\nMemory\n"
    free -h 2>/dev/null || true
    printf "\nFilesystems\n"
    df -hT 2>/dev/null || true
    printf "\nMounts\n"
    findmnt 2>/dev/null || mount 2>/dev/null || true
'

if command -v mdatp >/dev/null 2>&1; then
    run_bounded_capture 60 "MDE version" "${WORK_DIR}/mdatp-version.txt" \
        sh -c 'mdatp health --field app_version 2>/dev/null || mdatp version'
    run_bounded_capture 120 "MDE health" "${WORK_DIR}/mdatp-health.txt" mdatp health
    run_bounded_capture 180 "MDE connectivity test" "${WORK_DIR}/mdatp-connectivity.txt" mdatp connectivity test
    run_bounded_capture 60 "MDE exclusions" "${WORK_DIR}/mdatp-exclusions.txt" mdatp exclusion list
    run_bounded_capture 60 "MDE threats" "${WORK_DIR}/mdatp-threats.txt" mdatp threat list

    mkdir -p "${WORK_DIR}/mdatp-diagnostic"
    run_bounded_capture 600 "Native MDE diagnostic package" \
        "${WORK_DIR}/mdatp-diagnostic-command.txt" \
        mdatp diagnostic create --path "${WORK_DIR}/mdatp-diagnostic"
else
    record_error "The mdatp command was not found."
fi

ANALYZER="/opt/microsoft/mdatp/tools/client_analyzer/binary/MDESupportTool"
if [ -x "$ANALYZER" ]; then
    mkdir -p "${WORK_DIR}/client-analyzer"
    run_bounded_capture 900 "Microsoft Client Analyzer" \
        "${WORK_DIR}/client-analyzer-command.txt" \
        "$ANALYZER" --bypass-disclaimer --diagnostic --outdir "${WORK_DIR}/client-analyzer"
else
    printf 'The shipped Client Analyzer was not found at %s.\n' "$ANALYZER" \
        >"${WORK_DIR}/client-analyzer-not-available.txt"
    printf 'It is included with MDE agent version 101.25082.0000 or later.\n' \
        >>"${WORK_DIR}/client-analyzer-not-available.txt"
fi

if command -v systemctl >/dev/null 2>&1; then
    run_capture "MDE service status" "${WORK_DIR}/mdatp-service.txt" \
        systemctl status mdatp --no-pager
    run_capture "MDE service properties" "${WORK_DIR}/mdatp-service-properties.txt" \
        systemctl show mdatp --no-pager \
        --property=ActiveState,SubState,UnitFileState,MainPID,ExecMainCode,ExecMainStatus,Result,Restart,TasksCurrent,MemoryCurrent
fi

if command -v journalctl >/dev/null 2>&1; then
    run_bounded_capture 120 "MDE journal for the last 24 hours" \
        "${WORK_DIR}/mdatp-journal.txt" \
        journalctl -u mdatp --since "24 hours ago" --no-pager --utc
fi

run_capture "Network configuration" "${WORK_DIR}/network.txt" sh -c '
    printf "Addresses\n"
    ip address show 2>/dev/null || ifconfig -a 2>/dev/null || true
    printf "\nRoutes\n"
    ip route show table all 2>/dev/null || route -n 2>/dev/null || true
    printf "\nDNS configuration\n"
    resolvectl status 2>/dev/null || cat /etc/resolv.conf 2>/dev/null || true
    printf "\nListening and connected sockets\n"
    ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true
'

run_capture "Package information" "${WORK_DIR}/packages.txt" sh -c '
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f="${Package}\t${Version}\t${Architecture}\n" mdatp 2>/dev/null || true
    fi
    if command -v rpm >/dev/null 2>&1; then
        rpm -qi mdatp 2>/dev/null || true
    fi
    if command -v apk >/dev/null 2>&1; then
        apk info -a mdatp 2>/dev/null || true
    fi
'

{
    printf 'Proxy environment variable presence\n'
    for proxy_name in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY; do
        if printenv "$proxy_name" >/dev/null 2>&1; then
            printf '%s: SET (value redacted)\n' "$proxy_name"
        else
            printf '%s: not set\n' "$proxy_name"
        fi
    done
} >"${WORK_DIR}/proxy-environment.txt"

find "$WORK_DIR" -maxdepth 4 -type f -printf '%p\t%s bytes\n' 2>/dev/null \
    | sort >"${WORK_DIR}/file-inventory.txt"

{
    printf '\nWarnings recorded: %s\n' "$ERROR_COUNT"
    printf 'UTC completed: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} >>"$SUMMARY_FILE"

if [ "$ERROR_COUNT" -eq 0 ]; then
    OVERALL_RESULT="PASS"
    RESULT_CLASS="pass"
else
    OVERALL_RESULT="COMPLETED WITH WARNINGS"
    RESULT_CLASS="warn"
fi

cat >"$REPORT_FILE" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MDE Linux Diagnostic Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; background: #f8fafc; }
h1, h2 { color: #0f172a; }
.card { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
.pass { color: #166534; font-weight: bold; }
.warn { color: #a16207; font-weight: bold; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 6px; max-height: 32rem; overflow: auto; }
details { margin-bottom: 0.75rem; }
summary { cursor: pointer; font-weight: bold; padding: 0.5rem; }
</style>
</head>
<body>
<h1>Microsoft Defender for Endpoint Linux Diagnostic Report</h1>
<div class="card">
<p><strong>Device:</strong> $(html_escape_text "$HOST_NAME")</p>
<p><strong>Completed UTC:</strong> $(date -u '+%Y-%m-%dT%H:%M:%SZ')</p>
<p><strong>Result:</strong> <span class="$RESULT_CLASS">$OVERALL_RESULT</span></p>
<p><strong>Warnings:</strong> $ERROR_COUNT</p>
<p>The complete Microsoft diagnostic archives remain in this package for support escalation.</p>
</div>
<div class="card">
<h2>Primary findings</h2>
<details open><summary>Summary and platform support</summary><pre>$(html_escape_file "$SUMMARY_FILE")</pre></details>
<details open><summary>MDE connectivity</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-connectivity.txt")</pre></details>
<details open><summary>MDE health</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-health.txt")</pre></details>
<details><summary>MDE version</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-version.txt")</pre></details>
<details><summary>MDE service</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-service.txt")</pre></details>
<details><summary>MDE journal, previous 24 hours</summary><pre>$(html_escape_file "${WORK_DIR}/mdatp-journal.txt")</pre></details>
<details><summary>Network configuration</summary><pre>$(html_escape_file "${WORK_DIR}/network.txt")</pre></details>
<details><summary>System information</summary><pre>$(html_escape_file "${WORK_DIR}/system.txt")</pre></details>
<details><summary>Package information</summary><pre>$(html_escape_file "${WORK_DIR}/packages.txt")</pre></details>
<details><summary>Proxy environment</summary><pre>$(html_escape_file "${WORK_DIR}/proxy-environment.txt")</pre></details>
<details><summary>Supported Linux versions</summary><pre>$(html_escape_file "${WORK_DIR}/supported-linux-versions.txt")</pre></details>
<details><summary>Collected file inventory</summary><pre>$(html_escape_file "${WORK_DIR}/file-inventory.txt")</pre></details>
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
printf 'Warnings: %s\n' "$ERROR_COUNT"
printf 'Saved: %s\n' "$ARCHIVE_PATH"
printf 'Retrieve with: getfile "%s"\n' "$ARCHIVE_PATH"
exit 0
