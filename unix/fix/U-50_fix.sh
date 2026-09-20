#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-50"
readonly ITEM_TITLE="DNS ZoneTransfer 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 호스트(2차 네임서버)를 허용할지는 관리자 판단이 반드시 필요하며, named.conf 변경 후 reload/reconfig 가 필요해 승인이 필요함"
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
    local offenders=() any_allow_transfer_found="false"
    for c in "${confs[@]}"; do
        [ -z "$c" ] && continue
        if grep -Eq '^[[:space:]]*allow-transfer[[:space:]]*\{' "$c" 2>/dev/null; then
            any_allow_transfer_found="true"
            grep -EA1 '^[[:space:]]*allow-transfer[[:space:]]*\{' "$c" 2>/dev/null | grep -qi 'any' \
                && offenders+=("${c}")
        fi
    done
    if [ "$any_allow_transfer_found" = "false" ]; then
        CHECK_DETAIL="점검된 설정 파일 어디에도 allow-transfer 제한이 없어 기본 정책(전체 허용)이 적용됨."
        return "$KISA_EXIT_VULN"
    fi
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="Zone Transfer 가 전체 허용으로 설정된 곳 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="확인된 allow-transfer 설정이 특정 호스트로 제한되어 있음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 허용할 2차 네임서버 목록에 대한 판단과 named reload 가 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 와 KISA_U50_ALLOWED_TRANSFER_HOSTS(허용할 2차 네임서버 IP, 콤마 구분)를 함께 지정해 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if [ -z "${KISA_U50_ALLOWED_TRANSFER_HOSTS:-}" ]; then
        FIX_DETAIL="승인은 되었으나 KISA_U50_ALLOWED_TRANSFER_HOSTS 가 지정되지 않아 조치를 보류함(정상 2차 네임서버까지 차단되는 위험을 피하기 위한 안전장치)."
        return 1
    fi

    local confs
    mapfile -t confs < <(_find_named_confs)
    local target_conf=""
    for c in "${confs[@]}"; do
        [ -w "$c" ] && { target_conf="$c"; break; }
    done
    if [ -z "$target_conf" ]; then
        FIX_DETAIL="쓰기 가능한 named 설정 파일을 찾지 못해 조치를 수행할 수 없음."
        return 2
    fi

    local hosts
    hosts="$(printf '%s' "$KISA_U50_ALLOWED_TRANSFER_HOSTS" | tr ',' ';')"
    local backup="${target_conf}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$target_conf" "$backup" 2>/dev/null

    if grep -Eq '^[[:space:]]*allow-transfer[[:space:]]*\{' "$target_conf"; then
        sed -i -E "s/^([[:space:]]*allow-transfer[[:space:]]*\{)[^}]*(\};?)/\1 ${hosts}; \2/" "$target_conf"
    elif grep -qE '^[[:space:]]*options[[:space:]]*\{' "$target_conf"; then
        sed -i -E "0,/^[[:space:]]*options[[:space:]]*\{/s//&\n\tallow-transfer { ${hosts}; };/" "$target_conf"
    else
        printf '\noptions {\n\tallow-transfer { %s; };\n};\n' "$hosts" >> "$target_conf"
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

    FIX_DETAIL="${target_conf} 의 allow-transfer 를 '${hosts}' 로 제한함(백업: ${backup}, reload $( [ "$reloaded" = "true" ] && echo 완료 || echo 실패/수동필요 ))."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-50 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
