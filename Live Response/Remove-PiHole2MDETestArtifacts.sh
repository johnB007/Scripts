#!/usr/bin/env bash
#
# Remove only the exact PiHole2 MDE diagnostic artifacts created during the
# September 29, 2026 Live Response validation.
# Keep this file LF only. CRLF line endings cause Bash parser failures.
#
# Live Response:
#   run Remove-PiHole2MDETestArtifacts.sh -parameters "--confirm"

set -u
set -o pipefail
umask 077

if [ "${1:-}" != "--confirm" ]; then
    printf 'No files were deleted. Explicit confirmation is required.\n'
    printf 'Run: run Remove-PiHole2MDETestArtifacts.sh -parameters "--confirm"\n'
    exit 2
fi

ARTIFACTS=(
    "/tmp/IL5MDEConnectivity_PiHole2_20260929T230746Z.tar.gz"
    "/tmp/MDELinuxDiagnostics_PiHole2_20260929T230932Z.tar.gz"
    "/tmp/IL5MDEConnectivity_PiHole2_20260930T012656Z.html"
    "/tmp/IL5MDEConnectivity_PiHole2_20260930T012656Z.tar.gz"
    "/tmp/MDELinuxDiagnostics_PiHole2_20260930T013237Z.html"
    "/tmp/MDELinuxDiagnostics_PiHole2_20260930T013237Z.tar.gz"
)

REMOVED=0
NOT_FOUND=0
FAILED=0
FREED_BYTES=0

for artifact in "${ARTIFACTS[@]}"; do
    if [ -f "$artifact" ] || [ -L "$artifact" ]; then
        artifact_bytes="$(stat -c '%s' "$artifact" 2>/dev/null || printf '0')"
        if rm -f -- "$artifact" && [ ! -e "$artifact" ]; then
            REMOVED=$((REMOVED + 1))
            case "$artifact_bytes" in
                ''|*[!0-9]*) artifact_bytes=0 ;;
            esac
            FREED_BYTES=$((FREED_BYTES + artifact_bytes))
            printf 'REMOVED: %s (%s bytes)\n' "$artifact" "$artifact_bytes"
        else
            FAILED=$((FAILED + 1))
            printf 'FAILED: %s\n' "$artifact" >&2
        fi
    else
        NOT_FOUND=$((NOT_FOUND + 1))
        printf 'NOT FOUND: %s\n' "$artifact"
    fi
done

printf 'Removed: %s\n' "$REMOVED"
printf 'Not found: %s\n' "$NOT_FOUND"
printf 'Failed: %s\n' "$FAILED"
printf 'Freed bytes: %s\n' "$FREED_BYTES"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
