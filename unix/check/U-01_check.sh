#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-01"
readonly ITEM_TITLE="root 계정 원격 접속 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="sshd 설정 적용을 위해 서비스 reload/restart 가 필요하며, 원격 접속 정책이 즉시 변경되어 관리자의 재접속 경로에 영향을 줄 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local sshd_config="/etc/ssh/sshd_config"
    local val=""

    if ! command -v sshd >/dev/null 2>&1 && [ ! -r "$sshd_config" ]; then
        CHECK_DETAIL="sshd 및 sshd_config 를 찾을 수 없어 SSH 서비스가 설치되어 있지 않은 것으로 판단됨. 원격 root 접속 경로가 존재하지 않으므로 양호."
        return "$KISA_EXIT_GOOD"
    fi

    if command -v sshd >/dev/null 2>&1; then
        val="$(sshd -T 2>/dev/null | awk '/^permitrootlogin[[:space:]]/{print $2; exit}')"
    fi

    if [ -z "$val" ]; then
        if [ ! -r "$sshd_config" ]; then
            CHECK_DETAIL="sshd 는 존재하나 ${sshd_config} 를 읽을 수 없어 판정이 불가능함."
            return "$KISA_EXIT_FAIL"
        fi
        val="$(grep -iE '^[[:space:]]*PermitRootLogin[[:space:]]' "$sshd_config" 2>/dev/null | tail -n1 | awk '{print $2}')"
    fi

    val="$(printf '%s' "${val:-}" | tr '[:upper:]' '[:lower:]')"

    case "$val" in
        no|prohibit-password|without-password)
            CHECK_DETAIL="PermitRootLogin 이 '${val}' 로 설정되어 root 계정의 직접 원격(SSH) 접속이 제한되어 있음."
            return "$KISA_EXIT_GOOD"
            ;;
        yes)
            CHECK_DETAIL="PermitRootLogin 이 'yes' 로 설정되어 root 계정의 SSH 직접 접속이 허용되어 있음."
            return "$KISA_EXIT_VULN"
            ;;
        "")
            CHECK_DETAIL="PermitRootLogin 설정이 존재하지 않아 OpenSSH 기본값(버전에 따라 prohibit-password 또는 yes)이 적용됨. 명시적 제한이 없어 취약으로 판단."
            return "$KISA_EXIT_VULN"
            ;;
        *)
            CHECK_DETAIL="PermitRootLogin 값 '${val}' 을(를) 해석할 수 없어 취약으로 보수적으로 판단."
            return "$KISA_EXIT_VULN"
            ;;
    esac
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아(점검 사이 설정이 변경됨) 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
