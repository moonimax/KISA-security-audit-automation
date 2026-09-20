#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-32"
readonly ITEM_TITLE="홈 디렉토리로 지정한 디렉토리의 존재 관리"
readonly ACTION_TAG="자동조치"
readonly IMPACT="존재하지 않는 홈 디렉토리를 생성만 하는 비파괴적 변경으로 서비스 재시작이 불필요함. 기존 데이터를 덮어쓰거나 삭제하지 않음"
readonly SEVERITY="하"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local offenders=() count=0
    while IFS=: read -r uname _ _ _ _ home shell; do
        [ -z "$home" ] && continue
        [[ "$shell" =~ (nologin|false)$ ]] && continue
        if [ ! -d "$home" ]; then
            count=$((count + 1))
            [ "${#offenders[@]}" -lt 15 ] && offenders+=("${uname}:${home}")
        fi
    done < /etc/passwd

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="홈 디렉토리가 존재하지 않는 로그인 가능 계정 ${count}건(최대 15건 표시) 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="로그인 가능한 모든 계정의 홈 디렉토리가 실제로 존재함."
    return "$KISA_EXIT_GOOD"
}

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return 0
    fi
    if [ "$current" -eq "$KISA_EXIT_FAIL" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return 2
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local fixed=0 failed=0 created_list=""
    while IFS=: read -r uname _ uid gid _ home shell; do
        [ -z "$home" ] && continue
        [[ "$shell" =~ (nologin|false)$ ]] && continue
        if [ ! -d "$home" ]; then
            if mkdir -p "$home" 2>/dev/null && chown "${uid}:${gid}" "$home" 2>/dev/null && chmod 750 "$home" 2>/dev/null; then
                fixed=$((fixed + 1))
                created_list="${created_list}${created_list:+,}${uname}:${home}"
            else
                failed=$((failed + 1))
            fi
        fi
    done < /etc/passwd

    log_info "홈 디렉토리 생성: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 계정을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    if [ "$failed" -gt 0 ] && [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="홈 디렉토리 생성에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="존재하지 않던 홈 디렉토리 ${fixed}건을 생성함(소유자=UID:GID, 권한=750, 실패 ${failed}건): ${created_list}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-32 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
