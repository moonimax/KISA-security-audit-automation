#!/usr/bin/env bash

if [ -n "${__KISA_WEB_DETECT_LOADED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
__KISA_WEB_DETECT_LOADED=1

set -u

webdetect_apache_ctl() {
    local b
    for b in apache2ctl apachectl httpd; do
        if command -v "$b" >/dev/null 2>&1; then
            command -v "$b"
            return 0
        fi
    done
    return 1
}

webdetect_apache_present() {
    webdetect_apache_ctl >/dev/null 2>&1 && return 0
    [ -d /etc/apache2 ] && return 0
    [ -d /etc/httpd ] && return 0
    return 1
}

webdetect_apache_mainconf() {
    local c
    for c in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /usr/local/apache2/conf/httpd.conf; do
        if [ -r "$c" ]; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

webdetect_apache_active_confs() {
    local main
    main="$(webdetect_apache_mainconf 2>/dev/null || true)"
    [ -n "$main" ] && printf '%s\n' "$main"

    local d
    for d in /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/apache2/mods-enabled \
             /etc/httpd/conf.d /etc/httpd/conf.modules.d; do
        if [ -d "$d" ]; then
            find -L "$d" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.load' \) 2>/dev/null
        fi
    done
}

webdetect_apache_docroot() {
    local root=""
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        local v
        v="$(grep -iE '^[[:space:]]*DocumentRoot[[:space:]]' "$f" 2>/dev/null | tail -n1 \
             | awk '{$1=""; print}' | sed -e 's/^[[:space:]]*//' -e 's/"//g' -e 's/[[:space:]]*$//')"
        [ -n "$v" ] && root="$v"
    done < <(webdetect_apache_active_confs)
    [ -n "$root" ] && printf '%s' "$root" && return 0
    printf '/var/www/html'
    return 0
}

webdetect_apache_running_as_root() {
    command -v ps >/dev/null 2>&1 || return 1
    ps -eo comm,user 2>/dev/null | awk '$1=="apache2" || $1=="httpd" {print $2}' | grep -qx root
}

webdetect_nginx_present() {
    command -v nginx >/dev/null 2>&1 && return 0
    [ -d /etc/nginx ] && return 0
    return 1
}

webdetect_nginx_mainconf() {
    if [ -r /etc/nginx/nginx.conf ]; then
        printf '/etc/nginx/nginx.conf'
        return 0
    fi
    return 1
}

webdetect_nginx_active_confs() {
    local main
    main="$(webdetect_nginx_mainconf 2>/dev/null || true)"
    [ -n "$main" ] && printf '%s\n' "$main"

    local d
    for d in /etc/nginx/conf.d /etc/nginx/sites-enabled; do
        if [ -d "$d" ]; then
            find -L "$d" -maxdepth 1 -type f -name '*.conf' 2>/dev/null
            find -L "$d" -maxdepth 1 -type f ! -name '*.*' 2>/dev/null
        fi
    done
}

webdetect_nginx_docroot() {
    local root=""
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        local v
        v="$(grep -E '^[[:space:]]*root[[:space:]]' "$f" 2>/dev/null | tail -n1 \
             | awk '{$1=""; print}' | sed -e 's/^[[:space:]]*//' -e 's/;.*$//' -e 's/[[:space:]]*$//')"
        [ -n "$v" ] && root="$v"
    done < <(webdetect_nginx_active_confs)
    [ -n "$root" ] && printf '%s' "$root" && return 0
    printf '/var/www/html'
    return 0
}

webdetect_nginx_running_as_root() {
    command -v ps >/dev/null 2>&1 || return 1
    ps -eo comm,user 2>/dev/null | awk '$1=="nginx" {print $2}' | grep -qx root
}

webdetect_tomcat_home() {
    local c
    for c in "${CATALINA_HOME:-}" /usr/share/tomcat /usr/share/tomcat9 /usr/share/tomcat10 \
             /opt/tomcat /opt/apache-tomcat /var/lib/tomcat9 /var/lib/tomcat10; do
        [ -n "$c" ] || continue
        if [ -d "$c" ] && { [ -f "$c/conf/server.xml" ] || [ -f "$c/conf/tomcat-users.xml" ]; }; then
            printf '%s' "$c"
            return 0
        fi
    done
    local found
    found="$(timeout 10 find -L /usr /opt /var/lib -maxdepth 4 -type f -name 'catalina.sh' 2>/dev/null \
             | head -n1 | xargs -r dirname 2>/dev/null | xargs -r dirname 2>/dev/null)"
    if [ -n "$found" ] && [ -d "$found" ]; then
        printf '%s' "$found"
        return 0
    fi
    return 1
}

webdetect_tomcat_present() {
    webdetect_tomcat_home >/dev/null 2>&1
}

webdetect_tomcat_users_xml() {
    local home
    home="$(webdetect_tomcat_home 2>/dev/null)" || return 1
    for c in "$home/conf/tomcat-users.xml" /etc/tomcat9/tomcat-users.xml /etc/tomcat10/tomcat-users.xml; do
        if [ -f "$c" ]; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

webdetect_tomcat_server_xml() {
    local home
    home="$(webdetect_tomcat_home 2>/dev/null)" || return 1
    for c in "$home/conf/server.xml" /etc/tomcat9/server.xml /etc/tomcat10/server.xml; do
        if [ -f "$c" ]; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

webdetect_tomcat_web_xml() {
    local home
    home="$(webdetect_tomcat_home 2>/dev/null)" || return 1
    for c in "$home/conf/web.xml" /etc/tomcat9/web.xml /etc/tomcat10/web.xml; do
        if [ -f "$c" ]; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

webdetect_any_httpd_present() {
    webdetect_apache_present && return 0
    webdetect_nginx_present && return 0
    return 1
}

webdetect_backup_file() {
    local target="$1"
    local backup="${target}.bak.$(date +%Y%m%d%H%M%S)"
    if cp -p "$target" "$backup" 2>/dev/null; then
        printf '%s' "$backup"
        return 0
    fi
    return 1
}

webdetect_apache_configtest() {
    local ctl
    ctl="$(webdetect_apache_ctl 2>/dev/null)" || return 0
    case "$ctl" in
        */httpd) "$ctl" -t >/dev/null 2>&1 ;;
        *) "$ctl" configtest >/dev/null 2>&1 ;;
    esac
}

webdetect_nginx_configtest() {
    command -v nginx >/dev/null 2>&1 || return 0
    nginx -t >/dev/null 2>&1
}

webdetect_apache_reload() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload apache2 >/dev/null 2>&1 && return 0
        systemctl reload httpd >/dev/null 2>&1 && return 0
    fi
    if command -v service >/dev/null 2>&1; then
        service apache2 reload >/dev/null 2>&1 && return 0
        service httpd reload >/dev/null 2>&1 && return 0
    fi
    return 1
}

webdetect_nginx_reload() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload nginx >/dev/null 2>&1 && return 0
    fi
    if command -v service >/dev/null 2>&1; then
        service nginx reload >/dev/null 2>&1 && return 0
    fi
    return 1
}

webdetect_sed_escape_repl() {
    printf '%s' "$1" | sed -e 's/[\\/&]/\\&/g'
}

webdetect_tomcat_restart() {
    if command -v systemctl >/dev/null 2>&1; then
        for svc in tomcat tomcat9 tomcat10; do
            systemctl restart "$svc" >/dev/null 2>&1 && return 0
        done
    fi
    return 1
}

webdetect_perm_exceeds() {
    local perm="$1" max="$2"
    [[ "$perm" =~ ^[0-7]{3,4}$ ]] || return 2
    [[ "$max" =~ ^[0-7]{3,4}$ ]] || return 2
    local perm_dec=$((8#$perm)) max_dec=$((8#$max))
    local extra=$(( perm_dec & ~max_dec & 0777 ))
    [ "$extra" -ne 0 ]
}
