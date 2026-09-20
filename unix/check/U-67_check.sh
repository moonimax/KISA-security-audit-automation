#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-67"
readonly ITEM_TITLE="로그 디렉터리 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="디렉토리/파일 소유자 및 권한만 변경되며 서비스 재시작이 불필요함. 로깅 데몬은 이미 열린 파일 디스크립터에 계속 기록하므로 진행 중인 로그 기록에는 영향이 없음"
readonly SEVERITY="중"
readonly LOG_DIR="/var/log"
readonly LOG_FILES=(/var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure)

CHECK_DETAIL=""

do_check() {
    [ -d "$LOG_DIR" ] || { CHECK_DETAIL="$LOG_DIR가 없어 판정 불가능."; return "$KISA_EXIT_FAIL"; }
    local bad="" f owner mode
    owner="$(stat -L -c '%U' "$LOG_DIR" 2>/dev/null)"; mode="$(stat -L -c '%a' "$LOG_DIR" 2>/dev/null)"
    if [ "$owner" != root ] || [ $((8#$mode & 8#002)) -ne 0 ]; then
        bad="$LOG_DIR(owner=$owner,perm=$mode)"
    fi
    while IFS= read -r -d '' f; do
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"; mode="$(stat -L -c '%a' "$f" 2>/dev/null)"
        if [ "$owner" != root ] || [ $((8#$mode & 8#037)) -ne 0 ]; then bad="${bad}${bad:+,}$f(owner=$owner,perm=$mode)"; fi
    done < <(find "$LOG_DIR" -xdev -type f -print0 2>/dev/null)
    if [ -n "$bad" ]; then CHECK_DETAIL="로그 디렉터리/파일 소유권·권한 기준 위반: $bad"; return "$KISA_EXIT_VULN"; fi
    CHECK_DETAIL="$LOG_DIR는 root 소유/other 쓰기 금지이고 전체 로그 파일은 root 소유/640 이하."; return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
