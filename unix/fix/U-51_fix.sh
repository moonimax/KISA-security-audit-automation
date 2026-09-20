#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-51"
readonly ITEM_TITLE="DNS 서비스의 취약한 동적 업데이트 설정 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 클라이언트(DHCP 서버 등)에 동적 업데이트가 필요한지 관리자 판단이 필요하며, named.conf 변경 후 reload/reconfig 가 필요해 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

_find_named_confs() {
    local confs=()
    for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local; do
        [ -r "$f" ] && confs+=("$f")
    done
    printf '%s\n' "${confs[@]}"
}

do_check() {
    local confs
    mapfile -t confs < <(_find_named_confs)
    if ! command -v named >/dev/null 2>&1 && { [ "${#confs[@]}" -eq 0 ] || { [ "${#confs[@]}" -eq 1 ] && [ -z "${confs[0]}" ]; }; }; then
        CHECK_DETAIL="named(BIND) 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "${#confs[@]}" -eq 0 ] || { [ "${#confs[@]}" -eq 1 ] && [ -z "${confs[0]}" ]; }; then
        CHECK_DETAIL="named 는 설치되어 있으나 설정 파일을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local offenders=()
    for c in "${confs[@]}"; do
        [ -z "$c" ] && continue
        if grep -Eq '^[[:space:]]*allow-update[[:space:]]*\{' "$c" 2>/dev/null; then
            grep -E '^[[:space:]]*allow-update[[:space:]]*\{' "$c" 2>/dev/null | grep -qi 'any' && offenders+=("$c")
        fi
    done
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="동적 업데이트가 전체 허용으로 설정된 곳 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="allow-update 가 없거나 전체 허용('any')으로 설정되어 있지 않음."
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
    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): named reload 및 동적 업데이트 필요 여부 판단이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local confs
    mapfile -t confs < <(_find_named_confs)
    local fixed=0 backups=""

    for c in "${confs[@]}"; do
        [ -z "$c" ] && continue
        [ -w "$c" ] || continue
        if grep -Eq '^[[:space:]]*allow-update[[:space:]]*\{' "$c" 2>/dev/null \
            && grep -E '^[[:space:]]*allow-update[[:space:]]*\{' "$c" 2>/dev/null | grep -qi 'any'; then
            local backup="${c}.bak.$(date +%Y%m%d%H%M%S)"
            cp -p "$c" "$backup" 2>/dev/null
            sed -i -E "s/^([[:space:]]*allow-update[[:space:]]*\{)[^}]*(\};?)/\1 none; \2/" "$c"
            fixed=$((fixed + 1))
            backups="${backups}${backups:+,}${backup}"
        fi
    done

    if [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="조치 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local reloaded="false"
    if command -v rndc >/dev/null 2>&1; then
        rndc reconfig >/dev/null 2>&1 && reloaded="true"
    fi
    if [ "$reloaded" = "false" ] && command -v systemctl >/dev/null 2>&1; then
        restart_active_services named bind9 && reloaded="true"
    fi

    if [ "$reloaded" = "false" ]; then
        FIX_DETAIL="BIND 설정 파일은 변경했으나 실행 중 데몬 반영에 실패함."
        return 2
    fi

    FIX_DETAIL="${fixed}건의 allow-update 를 { none; } 으로 교체함(백업: ${backups}, reload $( [ "$reloaded" = "true" ] && echo 완료 || echo 실패/수동필요 ))."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-51 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
