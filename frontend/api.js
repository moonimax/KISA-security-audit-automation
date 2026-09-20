
(function (global) {
  "use strict";

  const browserHost = global.location && global.location.hostname
    ? global.location.hostname
    : "127.0.0.1";
  const defaultApiPort = global.location && global.location.port === "8081" ? "8001" : "8000";
  const API_BASE = global.SSAP_API_BASE || `http://${browserHost}:${defaultApiPort}`;
  let authToken = null;

  const MANUAL_FIX = {
    "U-01": `# /etc/ssh/sshd_config 수정
PermitRootLogin no

# 설정 반영
systemctl restart sshd`,
    "U-05": `# UID가 0인 계정을 사용하지 않는 UID로 변경 (예: 대상 계정 vulnu05)
usermod -u 1010 vulnu05

# usermod가 실패하면(로그인 중 계정 등) /etc/passwd를 직접 수정`,
    "U-06": `# /etc/pam.d/su 에 wheel 그룹 제한 추가
auth required pam_wheel.so use_uid group=wheel

# su 실행 권한을 wheel 그룹으로 제한
chown root:wheel /bin/su
chmod 4750 /bin/su`,
    "U-17": `# 소유자가 다른 심볼릭 링크 확인 후 소유자 일치시키기
find / -type l -xtype l 2>/dev/null
chown root:root <해당 심볼릭 링크 경로>`,
    "U-24": `# crontab 소유자 및 권한 재설정
chown root:root /etc/crontab
chmod 640 /etc/crontab`,
    "U-33": `# /etc/login.defs 수정
PASS_MIN_LEN 8

# 기존 계정에는 다음 로그인/비밀번호 변경부터 적용됨`,
    "U-42": `# 불필요한 서비스 중지 및 비활성화 (예: telnet)
systemctl stop telnet.socket
systemctl disable telnet.socket`,
    "U-53": `# /etc/ssh/sshd_config 수정
AllowUsers kisa_audit@192.168.0.0/24

# 설정 반영
systemctl restart sshd`,
    "WEB-04": `# Apache 예시 — 디렉터리 리스팅 비활성화
# httpd.conf 또는 해당 VirtualHost 블록에 추가
Options -Indexes

# 설정 반영
systemctl restart httpd    # 또는 apache2`,
    "D-18": `# MySQL 예시 — PUBLIC 성격의 과도한 권한 회수
REVOKE SELECT ANY TABLE, CREATE ANY PROCEDURE FROM 'app_user'@'%';
FLUSH PRIVILEGES;

# 애플리케이션에서 실제로 필요한 권한인지 먼저 확인할 것`,
  };

  function respond(value){
    return Promise.resolve(value);
  }

  async function requestBackend(path, options={}){
    const headers=Object.assign({},options.headers || {});
    if(authToken) headers.Authorization=`Bearer ${authToken}`;
    const res = await fetch(API_BASE + path,Object.assign({},options,{headers}));
    if(!res.ok){
      let detail = "";
      try{ detail = (await res.json()).detail || ""; }catch(e){  }
      throw new Error(detail || `백엔드 요청 실패: ${res.status} ${res.statusText}`);
    }
    if(res.status === 204) return null;
    return res.json();
  }
  function postJson(path, body){
    return requestBackend(path, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify(body)
    });
  }

  const API = {

    async login(id, password){
      const response=await postJson("/api/auth/login", { login_id:id, password });
      authToken=response.token || null;
      return response;
    },
    async logout(){
      try{ if(authToken) await postJson("/api/auth/logout", {}); }
      finally{ authToken=null; }
    },

    getManualFixMap(){
      return respond(MANUAL_FIX);
    },

    getHosts(){
      return requestBackend("/api/hosts");
    },
    getCheckRuns(){
      return requestBackend("/api/check-runs");
    },
    addHost({ ip, hostname, domains }){
      return postJson("/api/hosts", { ip, hostname: hostname || "미확인", domains });
    },
    removeHost(ip){
      return requestBackend(`/api/hosts/${encodeURIComponent(ip)}`, { method:"DELETE" });
    },

    getResults(host){
      const qs = host ? `?host=${encodeURIComponent(host)}` : "";
      return requestBackend(`/api/results${qs}`);
    },

    startCheckJob(ips, domains=["ALL"]){
      return postJson("/api/jobs/check", { ips, domains });
    },
    startCheckOnlyJob(ips, domains=["ALL"]){
      return postJson("/api/jobs/check-only", { ips, domains });
    },
    startRemediateJob(items){
      return postJson("/api/jobs/remediate", { items });
    },
    getJob(jobId){
      return requestBackend(`/api/jobs/${encodeURIComponent(jobId)}`);
    },
    getJobs(){ return requestBackend("/api/jobs"); },
    scanSshKey(ip){ return postJson(`/api/hosts/${encodeURIComponent(ip)}/ssh-key/scan`, {}); },
    approveSshKey(ip, { trustedFingerprint, password }){
      return postJson(`/api/hosts/${encodeURIComponent(ip)}/ssh-key/approve`, {
        trusted_fingerprint:trustedFingerprint,
        password
      });
    },
    getSshKeyAudit(ip){
      return requestBackend(`/api/hosts/${encodeURIComponent(ip)}/ssh-key/audit`);
    },
    getSshCaStatus(){ return requestBackend("/api/ssh-ca/status"); },
    initializeSshCa(password){ return postJson("/api/ssh-ca/initialize", { password }); },
    deploySshCertificate(ip,password){ return postJson(`/api/hosts/${encodeURIComponent(ip)}/ssh-certificate/deploy`, { password }); },

    checkConnection(ip){ return postJson(`/api/hosts/${encodeURIComponent(ip)}/connection-check`, {}); },
    preflightHosts(ips){ return postJson("/api/preflight", { ips }); },
    evidenceUrl(jobId){ return `${API_BASE}/api/jobs/${encodeURIComponent(jobId)}/evidence`; },
    getEvidenceSummary(jobId){ return requestBackend(`/api/jobs/${encodeURIComponent(jobId)}/evidence-summary`); },

    getReportLog(){
      return requestBackend("/api/report-logs");
    },
    addReportLog(entry){
      return postJson("/api/report-logs", entry);
    },

    integratedReportUrl(host){
      const params = new URLSearchParams();
      if(host) params.set("host", host);
      params.set("_ts", String(Date.now()));
      return `${API_BASE}/api/reports/integrated.xlsx?${params.toString()}`;
    },

    changePassword({ loginId, current, next }){
      return postJson("/api/auth/change-password", {
        login_id:loginId,
        current_password:current,
        new_password:next
      });
    },
  };

  global.API = API;
})(window);
