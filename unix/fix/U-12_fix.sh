#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-12"
readonly ITEM_TITLE="세션 종료 시간 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="신규 로그인 셸 프로파일에만 적용되는 설정 파일 추가로 서비스 재시작이 불필요함. 이미 접속 중인 세션에는 영향이 없고, 신규 세션부터 유휴 시간 초과 시 자동 로그아웃됨"
readonly SEVERITY="중"
readonly TMOUT_LIMIT=600
readonly TMOUT_PROFILE_D="/etc/profile.d/99-kisa-tmout.sh"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local candidates=(/etc/profile /etc/bashrc /etc/csh.login)
    if [ -d /etc/profile.d ]; then
        while IFS= read -r -d '' f; do
            candidates+=("$f")
        done < <(find /etc/profile.d -maxdepth 1 -type f -name '*.sh' -print0 2>/dev/null)
    fi

    local min_val=""
    for f in "${candidates[@]}"; do
        [ -r "$f" ] || continue
        local val
        val="$(grep -E '^[[:space:]]*(export[[:space:]]+)?TMOUT[[:space:]]*=' "$f" 2>/dev/null \
            | grep -v '^[[:space:]]*#' | tail -n1 | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
        if [[ "$val" =~ ^[0-9]+$ ]]; then
            if [ -z "$min_val" ] || [ "$val" -lt "$min_val" ]; then
                min_val="$val"
            fi
        fi
    done

    if [ -z "$min_val" ]; then
        CHECK_DETAIL="TMOUT 설정을 어느 프로파일 파일에서도 찾을 수 없음."
        return "$KISA_EXIT_VULN"
    fi
    if [ "$min_val" -ge 1 ] && [ "$min_val" -le "$TMOUT_LIMIT" ]; then
        CHECK_DETAIL="TMOUT=${min_val}초 로 기준을 충족함."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="TMOUT=${min_val}초 로 ${TMOUT_LIMIT}초를 초과함."
    return "$KISA_EXIT_VULN"
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
    if [ ! -d /etc/profile.d ]; then
        FIX_DETAIL="/etc/profile.d 디렉토리가 없어 자동 조치를 수행하지 못함. 수동으로 /etc/profile 에 TMOUT=${TMOUT_LIMIT} 추가가 필요함."
        return 2
    fi

    {
        printf '# KISA U-12: 유휴 세션 자동 종료 설정 (자동조치 스크립트가 생성)\n'
        printf 'TMOUT=%s\n' "$TMOUT_LIMIT"
        printf 'readonly TMOUT 2>/dev/null\n'
        printf 'export TMOUT\n'
    } > "$TMOUT_PROFILE_D" 2>/dev/null

    if [ ! -s "$TMOUT_PROFILE_D" ]; then
        FIX_DETAIL="${TMOUT_PROFILE_D} 생성에 실패하여 조치를 완료하지 못함."
        return 2
    fi
    chmod 644 "$TMOUT_PROFILE_D" 2>/dev/null

    FIX_DETAIL="${TMOUT_PROFILE_D} 파일을 생성하여 TMOUT=${TMOUT_LIMIT} 을 적용함(신규 세션부터 유효)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-12 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
