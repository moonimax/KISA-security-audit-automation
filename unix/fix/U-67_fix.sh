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
FIX_DETAIL=""

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

do_fix() {
    do_check; local current=$?
    [ "$current" -eq "$KISA_EXIT_GOOD" ] && { FIX_DETAIL="이미 양호 상태."; return 0; }
    [ "$current" -eq "$KISA_EXIT_FAIL" ] && { FIX_DETAIL="점검 실패로 조치 중단."; return 2; }
    require_root || { FIX_DETAIL="root 권한 필요."; return 2; }
    local f owner mode fixed=0 failed=0
    owner="$(stat -L -c '%U' "$LOG_DIR" 2>/dev/null)"; mode="$(stat -L -c '%a' "$LOG_DIR" 2>/dev/null)"
    if [ "$owner" != root ] || [ $((8#$mode & 8#002)) -ne 0 ]; then
        if chown root:root "$LOG_DIR" 2>/dev/null && chmod 755 "$LOG_DIR" 2>/dev/null; then
            fixed=$((fixed+1))
        else
            failed=$((failed+1))
        fi
    fi
    while IFS= read -r -d '' f; do
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"; mode="$(stat -L -c '%a' "$f" 2>/dev/null)"
        if [ "$owner" != root ] || [ $((8#$mode & 8#037)) -ne 0 ]; then
            if chown root:root "$f" 2>/dev/null && chmod 640 "$f" 2>/dev/null; then fixed=$((fixed+1)); else failed=$((failed+1)); fi
        fi
    done < <(find "$LOG_DIR" -xdev -type f -print0 2>/dev/null)
    FIX_DETAIL="$LOG_DIR 내 전체 로그 파일 조치: 성공 $fixed건, 실패 $failed건."
    [ "$failed" -eq 0 ] || return 2
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-67 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
