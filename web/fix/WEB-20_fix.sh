#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-20"
readonly ITEM_TITLE="SSL/TLS 활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="유효한 인증서/개인키가 없으면 조치할 수 없으며, 잘못된 인증서 적용 시 접속 오류가 발생할 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

apache_ssl_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '<VirtualHost[^>]*:443' "$f" 2>/dev/null && grep -qiE '^[[:space:]]*SSLEngine[[:space:]]+on' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_ssl_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*listen[[:space:]]+.*443[[:space:]]+.*ssl' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" detail=""
    webdetect_apache_present && ! apache_ssl_enabled && { vuln="true"; detail="${detail}Apache SSL 미설정. "; }
    webdetect_nginx_present && ! nginx_ssl_enabled && { vuln="true"; detail="${detail}Nginx SSL 미설정. "; }
    CHECK_DETAIL="${detail:-SSL/TLS 활성화됨}"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
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

    if ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 유효한 인증서/개인키 경로 지정이 필요함. 승인 후 KISA_APPROVAL=true 와 KISA_WEB20_CERT_FILE/KISA_WEB20_KEY_FILE 을 함께 지정해 재실행하세요."
        return 1
    fi

    local cert="${KISA_WEB20_CERT_FILE:-/etc/ssl/certs/ssl-cert-snakeoil.pem}" key="${KISA_WEB20_KEY_FILE:-/etc/ssl/private/ssl-cert-snakeoil.key}"
    if [ ! -r "$cert" ] || [ ! -r "$key" ]; then
        FIX_DETAIL="지정된 인증서 또는 개인키 파일을 대상 호스트에서 읽을 수 없어 조치를 보류함(cert=${cert}, key=${key})."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local did_apache="false" did_nginx="false"
    if webdetect_apache_present && ! apache_ssl_enabled; then
        command -v a2enmod >/dev/null 2>&1 && a2enmod ssl >/dev/null 2>&1 || true
        local main; main="$(webdetect_apache_mainconf 2>/dev/null)"
        if [ -n "$main" ] && [ -w "$main" ]; then
            local backup; backup="$(webdetect_backup_file "$main")"
            if [ -n "$backup" ]; then
                cat >> "$main" <<EOF

<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile ${cert}
    SSLCertificateKeyFile ${key}
    SSLProtocol -all +TLSv1.2 +TLSv1.3
</VirtualHost>
EOF
                did_apache="true"
            fi
        fi
    fi

    if webdetect_nginx_present && ! nginx_ssl_enabled; then
        local nmain; nmain="$(webdetect_nginx_mainconf 2>/dev/null)"
        if [ -n "$nmain" ] && [ -w "$nmain" ] && grep -qE '^[[:space:]]*http[[:space:]]*\{' "$nmain"; then
            local nbackup; nbackup="$(webdetect_backup_file "$nmain")"
            if [ -n "$nbackup" ]; then
                local tmp; tmp="$(mktemp)"
                awk -v cert="$cert" -v key="$key" '
                    { print }
                    /^[[:space:]]*http[[:space:]]*\{/ && !done {
                        print "    server {"
                        print "        listen 443 ssl;"
                        print "        ssl_certificate " cert ";"
                        print "        ssl_certificate_key " key ";"
                        print "        ssl_protocols TLSv1.2 TLSv1.3;"
                        print "    }"
                        done=1
                    }
                ' "$nmain" > "$tmp" && mv "$tmp" "$nmain"
                did_nginx="true"
            fi
        fi
    fi

    if [ "$did_apache" != "true" ] && [ "$did_nginx" != "true" ]; then
        FIX_DETAIL="설정 파일에 쓸 수 없어 조치를 수행하지 못함."
        return 2
    fi

    local ok="true"
    [ "$did_apache" = "true" ] && ! webdetect_apache_configtest && ok="false"
    [ "$did_nginx" = "true" ] && ! webdetect_nginx_configtest && ok="false"

    if [ "$ok" != "true" ]; then
        FIX_DETAIL="443 SSL/TLS 설정이 문법 검증에 실패함. 백업 파일에서 수동 복구가 필요할 수 있음(자동 롤백은 설정 온전성을 보장하기 어려워 수행하지 않음)."
        return 2
    fi

    [ "$did_apache" = "true" ] && { webdetect_apache_reload || log_warn "Apache reload 실패"; }
    [ "$did_nginx" = "true" ] && { webdetect_nginx_reload || log_warn "Nginx reload 실패"; }

    FIX_DETAIL="지정된 인증서/개인키로 443 SSL/TLS VirtualHost/server 블록을 추가함(cert=${cert})."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-20 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
