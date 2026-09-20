#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-66"
readonly ITEM_TITLE="정책에 따른 시스템 로깅 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="로깅 규칙 추가 후 rsyslog 서비스 재시작이 필요하며, 반영 중 짧은 순간 로그 유실 가능성이 있어 관리자 승인이 필요함"
readonly SEVERITY="중"
readonly NEW_RULE_FILE="/etc/rsyslog.d/99-kisa-auth.conf"

CHECK_DETAIL=""
FIX_DETAIL=""

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

do_fix() {
    do_check; local current=$?
    [ "$current" -eq "$KISA_EXIT_GOOD" ] && { FIX_DETAIL="이미 양호 상태."; return 0; }
    [ "$current" -eq "$KISA_EXIT_FAIL" ] && { FIX_DETAIL="점검 실패로 조치 중단."; return 2; }
    if ! is_approved; then FIX_DETAIL="관리자 승인 후 전체 facility/level 정책을 추가하고 rsyslog를 재시작함."; return 1; fi
    require_root || { FIX_DETAIL="root 권한 필요."; return 2; }
    [ -d /etc/rsyslog.d ] || { FIX_DETAIL="/etc/rsyslog.d가 없어 rsyslog 미설치 가능."; return 2; }
    local backup=""; [ -e "$NEW_RULE_FILE" ] && { backup="${NEW_RULE_FILE}.bak.$(date +%Y%m%d%H%M%S)"; cp -p "$NEW_RULE_FILE" "$backup" || return 2; }
    {
      printf '%s\n' '# KISA U-66 facility/level logging policy'
      printf '%s\n' 'auth,authpriv.*                 /var/log/auth.log'
      printf '%s\n' 'mail.*                          -/var/log/mail.log'
      printf '%s\n' 'daemon.*                        -/var/log/daemon.log'
      printf '%s\n' 'cron.*                          -/var/log/cron.log'
      printf '%s\n' '*.alert                         /var/log/alert.log'
      printf '%s\n' '*.emerg                         :omusrmsg:*'
    } > "$NEW_RULE_FILE" || { FIX_DETAIL="정책 파일 작성 실패."; return 2; }
    if command -v rsyslogd >/dev/null 2>&1 && ! rsyslogd -N1 >/dev/null 2>&1; then
        [ -n "$backup" ] && cp -p "$backup" "$NEW_RULE_FILE" || rm -f "$NEW_RULE_FILE"
        FIX_DETAIL="rsyslog 문법 검증 실패로 롤백."; return 2
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart rsyslog >/dev/null 2>&1 || { FIX_DETAIL="rsyslog 재시작 실패."; return 2; }
        systemctl is-active rsyslog >/dev/null 2>&1 || { FIX_DETAIL="재시작 후 rsyslog 비활성."; return 2; }
    else FIX_DETAIL="정책 파일은 작성했으나 서비스 반영 도구가 없어 수동 재시작 필요."; return 1; fi
    FIX_DETAIL="전체 facility/level 정책 작성 및 rsyslog 재시작·활성 확인 완료. 백업: ${backup:-없음}."; return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-66 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
