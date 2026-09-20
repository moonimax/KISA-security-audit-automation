#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-66"
readonly ITEM_TITLE="정책에 따른 시스템 로깅 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="로깅 규칙 추가 후 rsyslog 서비스 재시작이 필요하며, 반영 중 짧은 순간 로그 유실 가능성이 있어 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""

_collect_rsyslog_confs() {
    local confs=()
    [ -e /etc/rsyslog.conf ] && confs+=(/etc/rsyslog.conf)
    [ -e /etc/syslog.conf ] && confs+=(/etc/syslog.conf)
    if [ -d /etc/rsyslog.d ]; then
        while IFS= read -r -d '' f; do confs+=("$f"); done \
            < <(find /etc/rsyslog.d -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
    fi
    printf '%s\n' "${confs[@]}"
}

do_check() {
    local confs text="" c missing=()
    mapfile -t confs < <(_collect_rsyslog_confs)
    [ "${#confs[@]}" -gt 0 ] && [ -n "${confs[0]:-}" ] || { CHECK_DETAIL="rsyslog/syslog 설정 없음."; return "$KISA_EXIT_VULN"; }
    for c in "${confs[@]}"; do [ -r "$c" ] && text="${text}$(printf '\n')$(grep -Ev '^[[:space:]]*(#|$)' "$c" 2>/dev/null)"; done
    printf '%s\n' "$text" | grep -Eq '(^|[,;[:space:]])(auth|authpriv)\.\*' || missing+=("auth/authpriv.*")
    printf '%s\n' "$text" | grep -Eq '(^|[,;[:space:]])mail\.\*' || missing+=("mail.*")
    printf '%s\n' "$text" | grep -Eq '(^|[,;[:space:]])(daemon|local[0-7])\.\*' || missing+=("daemon/local.*")
    printf '%s\n' "$text" | grep -Eq '(^|[,;[:space:]])cron\.\*' || missing+=("cron.*")
    printf '%s\n' "$text" | grep -Eq '(^|[,;[:space:]])\*\.(alert|emerg)' || missing+=("*.alert 또는 *.emerg")
    if [ "${#missing[@]}" -gt 0 ]; then CHECK_DETAIL="facility/level 로깅 정책 누락: $(IFS=','; echo "${missing[*]}")"; return "$KISA_EXIT_VULN"; fi
    local active=false svc
    if command -v systemctl >/dev/null 2>&1; then for svc in rsyslog syslog syslog-ng; do systemctl is-active "$svc" >/dev/null 2>&1 && active=true; done; fi
    [ "$active" = true ] || { CHECK_DETAIL="정책은 있으나 로깅 서비스 비활성."; return "$KISA_EXIT_VULN"; }
    CHECK_DETAIL="auth, mail, daemon/local, cron, alert/emerg 정책과 활성 로깅 서비스를 확인함."; return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
