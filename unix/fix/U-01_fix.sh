#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-01"
readonly ITEM_TITLE="root 계정 원격 접속 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="sshd 설정 적용을 위해 서비스 reload/restart 가 필요하며, 원격 접속 정책이 즉시 변경되어 관리자의 재접속 경로에 영향을 줄 수 있음"
readonly SEVERITY="상"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local val=""

    if ! command -v sshd >/dev/null 2>&1 && [ ! -r "$SSHD_CONFIG" ]; then
        CHECK_DETAIL="sshd 및 sshd_config 를 찾을 수 없어 SSH 서비스가 설치되어 있지 않은 것으로 판단됨."
        return "$KISA_EXIT_GOOD"
    fi

    if command -v sshd >/dev/null 2>&1; then
        val="$(sshd -T 2>/dev/null | awk '/^permitrootlogin[[:space:]]/{print $2; exit}')"
    fi

    if [ -z "$val" ]; then
        if [ ! -r "$SSHD_CONFIG" ]; then
            CHECK_DETAIL="${SSHD_CONFIG} 를 읽을 수 없어 판정이 불가능함."
            return "$KISA_EXIT_FAIL"
        fi
        val="$(grep -iE '^[[:space:]]*PermitRootLogin[[:space:]]' "$SSHD_CONFIG" 2>/dev/null | tail -n1 | awk '{print $2}')"
    fi

    val="$(printf '%s' "${val:-}" | tr '[:upper:]' '[:lower:]')"

    case "$val" in
        no|prohibit-password|without-password)
            CHECK_DETAIL="PermitRootLogin 이 '${val}' 로 설정되어 있음."
            return "$KISA_EXIT_GOOD"
            ;;
        yes)
            CHECK_DETAIL="PermitRootLogin 이 'yes' 로 설정되어 있음."
            return "$KISA_EXIT_VULN"
            ;;
        "")
            CHECK_DETAIL="PermitRootLogin 설정이 없어 기본값이 적용됨."
            return "$KISA_EXIT_VULN"
            ;;
        *)
            CHECK_DETAIL="PermitRootLogin 값 '${val}' 해석 불가."
            return "$KISA_EXIT_VULN"
            ;;
    esac
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): sshd 설정 변경 및 서비스 reload가 필요한 항목이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하거나, 수동으로 ${SSHD_CONFIG} 에 'PermitRootLogin no' 설정 후 sshd 를 reload 하세요."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    if [ ! -w "$SSHD_CONFIG" ] 2>/dev/null && [ ! -e "$SSHD_CONFIG" ]; then
        FIX_DETAIL="${SSHD_CONFIG} 파일이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local backup="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    if ! cp -p "$SSHD_CONFIG" "$backup" 2>/dev/null; then
        FIX_DETAIL="설정 파일 백업 실패로 조치를 중단함."
        return 2
    fi
    log_info "sshd_config 백업 완료: ${backup}"

    if grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]' "$SSHD_CONFIG"; then
        sed -i -E 's/^[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/I' "$SSHD_CONFIG"
    else
        printf '\nPermitRootLogin no\n' >> "$SSHD_CONFIG"
    fi

    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_backups=""
    if [ -d "$dropin_dir" ]; then
        local f
        for f in "$dropin_dir"/*.conf; do
            [ -e "$f" ] || continue
            grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]' "$f" || continue
            local dbackup="${f}.bak.$(date +%Y%m%d%H%M%S)"
            if ! cp -p "$f" "$dbackup" 2>/dev/null; then
                FIX_DETAIL="드롭인 설정(${f}) 백업 실패로 조치를 중단함. 메인 설정 백업: ${backup}"
                cp -p "$backup" "$SSHD_CONFIG"
                return 2
            fi
            sed -i -E 's/^([[:space:]]*)PermitRootLogin([[:space:]].*)/\1#PermitRootLogin\2 # KISA U-01: 메인 sshd_config 설정을 따르도록 비활성화됨/I' "$f"
            dropin_backups="${dropin_backups}${dropin_backups:+,}${f}->${dbackup}"
            log_info "드롭인 설정 ${f} 의 PermitRootLogin 지시자를 비활성화함(백업: ${dbackup})."
        done
    fi

    if command -v sshd >/dev/null 2>&1 && ! sshd -t 2>/dev/null; then
        cp -p "$backup" "$SSHD_CONFIG"
        if [ -n "$dropin_backups" ]; then
            local pair src dst
            IFS=',' read -ra _pairs <<< "$dropin_backups"
            for pair in "${_pairs[@]}"; do
                dst="${pair%%->*}"; src="${pair##*->}"
                cp -p "$src" "$dst" 2>/dev/null
            done
        fi
        log_error "sshd 설정 문법 검증 실패, 백업본으로 롤백함."
        FIX_DETAIL="변경된 설정이 sshd 문법 검증에 실패하여 백업본(${backup})으로 롤백함."
        return 2
    fi

    local reloaded="false"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload sshd >/dev/null 2>&1 && reloaded="true"
        [ "$reloaded" = "false" ] && systemctl reload ssh >/dev/null 2>&1 && reloaded="true"
    fi
    if [ "$reloaded" = "false" ] && command -v service >/dev/null 2>&1; then
        service sshd reload >/dev/null 2>&1 && reloaded="true"
        [ "$reloaded" = "false" ] && service ssh reload >/dev/null 2>&1 && reloaded="true"
    fi

    local dropin_note=""
    [ -n "$dropin_backups" ] && dropin_note=" 드롭인 설정 비활성화: ${dropin_backups}."

    if [ "$reloaded" = "true" ]; then
        FIX_DETAIL="PermitRootLogin no 로 설정을 변경하고 sshd 서비스 reload 까지 완료함.${dropin_note} 백업: ${backup}"
        return 0
    fi

    FIX_DETAIL="PermitRootLogin no로 파일은 변경했으나 sshd reload 실패.${dropin_note} 백업: ${backup}"
    return 2
}

do_fix
KISA_FIX_RC=$?
log_info "U-01 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
