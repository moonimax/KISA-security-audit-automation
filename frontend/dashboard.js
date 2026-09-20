(function(){
  "use strict";

  const SECURITY_SEV_WEIGHT = { "상":10, "중":8, "하":6 };
  const SEV_CLASS  = { "상":"high", "중":"mid", "하":"low" };
  const OS_LABEL = { rocky:"Rocky Linux", ubuntu:"Ubuntu" };
  const DOMAIN_BOX_CLASS = { UNIX:"domain-box-unix", WEB:"domain-box-web", DBMS:"domain-box-dbms", WINDOWS:"domain-box-windows" };

  let currentUser = null;
  let currentLoginId = null;
  let currentUserProfile = null;
  let selectedIps = new Set();
  let selectedCheckItems = new Set();
  let remediationUpdates = [];
  let remediationUpdateTime = null;
  let remediationScoreChange = null;
  let actionIpSort = { key:"time", direction:"desc" };
  let actionVulnSort = { key:"code", direction:"asc" };

  let itemMeta = {};
  let manualFix = {};
  let hosts = [];
  let results = [];
  let sshCaState = { ready:false };
  let registeredIps = [];
  let reportLog = [];
  let latestEvidenceJob = null;
  let evidenceJobs = [];
  let sshApprovalRow = null;

  let checkRuns = [];
  let dbResultsError = null;

  function domainOfCode(code){
    if(code.startsWith("WEB")) return "WEB";
    if(code.startsWith("D-")) return "DBMS";
    if(code.startsWith("W-")) return "WINDOWS";
    return "UNIX";
  }

  function buildItemMeta(rows){
    const meta = {};
    rows.forEach(r => {
      if(meta[r.code]) return;
      meta[r.code] = {
        domain: domainOfCode(r.code),
        title: r.title, severity: r.severity,
        action_tag: r.action_tag, impact: r.impact
      };
    });
    return meta;
  }

  async function reloadHostsAndResults(){
    const [hostList, resultRows, runRows, jobRows, caState] = await Promise.all([
      API.getHosts(), API.getResults(), API.getCheckRuns(), API.getJobs(), API.getSshCaStatus(),
    ]);
    sshCaState=caState;
    registeredIps = hostList.map(h => ({
      ip:h.ip, hostname:h.hostname, domains:h.domains,
      registeredAt:h.registered_at,
      sshIdentity:h.ssh_identity || { status:"unverified" },
      connectionStatus:h.connection_status || { status:"unknown" }
    })).sort((left, right) => (
      logTimeNumber(right.registeredAt) - logTimeNumber(left.registeredAt)
      || compareIpAddresses(left.ip, right.ip)
    ));
    results = resultRows.map(r => ({
      ...r,
      code:String(r.code || "").trim()
    }));
    itemMeta = buildItemMeta(resultRows);
    hosts = registeredIps.map(h => {
      const sample = resultRows.find(r => r.ip === h.ip);
      return { ip:h.ip, hostname:h.hostname, domains:h.domains, os_type: sample ? sample.os_type : "-" };
    });
    checkRuns = runRows;
    latestEvidenceJob = jobRows.find(job => job.evidence_available) || null;
    evidenceJobs = jobRows.filter(job => job.evidence_available);
    const latestActionJob = jobRows.find(job => job.result && Array.isArray(job.result.remediation_updates));
    if(latestActionJob && remediationUpdates.length === 0){
      remediationUpdates = latestActionJob.result.remediation_updates;
      remediationUpdateTime = formatLogTimestamp(new Date((latestActionJob.finished_at || latestActionJob.created_at)*1000).toISOString());
      remediationScoreChange = {initial:latestActionJob.result.initial_score,final:latestActionJob.result.final_score};
    }
    updateEvidenceButton();
    dbResultsError = null;

  }

  async function loadInitialData(){
    const fixes = await API.getManualFixMap();
    manualFix = fixes;
    reportLog = await API.getReportLog();
    await reloadHostsAndResults();
  }

  async function loadDbResults(){
    try{
      checkRuns = await API.getCheckRuns();
      dbResultsError = null;
    }catch(err){
      dbResultsError = err && err.message ? err.message : String(err);
    }
    renderDbResults();
  }

  async function pollJob(jobId, onTick){
    for(;;){
      const job = await API.getJob(jobId);
      if(onTick) onTick(job);
      if(job.status !== "running") return job;
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  function escapeHtml(str){
    return String(str).replace(/[&<>"']/g, s => ({
      "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"
    })[s]);
  }

  let appDialogResolve = null;
  const ERROR_NOTICE_STORAGE_KEY = "ssapCheckErrorNotifications";

  function loadErrorNotifications(){
    try{
      const parsed = JSON.parse(localStorage.getItem(ERROR_NOTICE_STORAGE_KEY) || "[]");
      return Array.isArray(parsed) ? parsed : [];
    }catch(_error){
      return [];
    }
  }

  function saveErrorNotifications(items){
    try{ localStorage.setItem(ERROR_NOTICE_STORAGE_KEY, JSON.stringify(items.slice(0, 20))); }
    catch(_error){  }
  }

  function recordErrorNotification(message){
    const text = String(message || "").trim();
    if(!text) return;
    const items = loadErrorNotifications();
    items.unshift({
      id:`error-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      message:text,
      created_at:new Date().toISOString(),
      read:false
    });
    saveErrorNotifications(items);
    renderCheckNotifications();
  }

  function closeAppDialog(confirmed){
    const overlay = document.getElementById("appDialogOverlay");
    if(overlay) overlay.classList.add("hidden");
    if(appDialogResolve){
      const resolve = appDialogResolve;
      appDialogResolve = null;
      resolve(Boolean(confirmed));
    }
  }

  function openAppDialog(message, { title="알림", confirm=false, commands=[], html=false, wide=false } = {}){
    const overlay = document.getElementById("appDialogOverlay");
    const cancel = document.getElementById("appDialogCancel");
    const confirmButton = document.getElementById("appDialogConfirm");
    const messageBox = document.getElementById("appDialogMessage");
    document.getElementById("appDialogTitle").textContent = title;
    if(html) messageBox.innerHTML = String(message || "");
    else messageBox.textContent = String(message || "");
    const commandList=Array.from(new Set((commands || []).map(value=>String(value || "").trim()).filter(Boolean)));
    const codeWrap=document.getElementById("appDialogCodeWrap");
    const code=document.getElementById("appDialogCode");
    const copy=document.getElementById("appDialogCopy");
    code.textContent=commandList.join("\n");
    codeWrap.classList.toggle("hidden",commandList.length === 0);
    copy.textContent="명령어 복사";
    copy.classList.remove("app-dialog-copy-success");
    cancel.classList.toggle("hidden", !confirm);
    confirmButton.textContent = confirm ? "계속" : "확인";
    document.getElementById("appDialogOverlay").querySelector(".app-dialog-modal")
      .classList.toggle("app-dialog-modal-wide", Boolean(wide));
    overlay.classList.remove("hidden");
    setTimeout(() => confirmButton.focus(), 0);
    return new Promise(resolve => {
      if(appDialogResolve) appDialogResolve(false);
      appDialogResolve = resolve;
    });
  }

  function alert(message){
    const text = String(message || "");
    if(/오류|실패/.test(text)) recordErrorNotification(text);
    void openAppDialog(text);
  }


  function preflightFixCommands(preflight){
    if(!preflight || !Array.isArray(preflight.hosts)) return [];
    return preflight.hosts.flatMap(host => (host.checks || [])
      .filter(check => check.status === "fail" && check.fix)
      .flatMap(check => check.fix.commands || []));
  }

  function preflightFixGuidance(preflight){
    if(!preflight || !Array.isArray(preflight.hosts)) return [];
    return Array.from(new Set(preflight.hosts.flatMap(host => (host.checks || [])
      .filter(check => check.status === "fail" && check.fix && check.fix.summary)
      .map(check => `${check.name}: ${check.fix.summary}`))));
  }

  function alertWithCommands(message, commands){
    const text=String(message || "");
    if(/오류|실패|차단/.test(text)) recordErrorNotification(text);
    void openAppDialog(text,{title:"오류 해결 안내",commands});
  }

  function showJobFailure(message,job){
    const guidance=preflightFixGuidance(job && job.preflight);
    const fullMessage=message+(guidance.length ? `\n\n--- 해결 방법 ---\n${guidance.join("\n")}` : "");
    alertWithCommands(fullMessage,preflightFixCommands(job && job.preflight));
  }

  function showAppConfirm(message){
    return openAppDialog(message, { title:"확인", confirm:true });
  }

  function initAppDialog(){
    document.getElementById("appDialogConfirm").addEventListener("click", () => closeAppDialog(true));
    document.getElementById("appDialogCancel").addEventListener("click", () => closeAppDialog(false));
    document.getElementById("appDialogCopy").addEventListener("click", async event => {
      const text=document.getElementById("appDialogCode").textContent;
      if(!text) return;
      try{
        await navigator.clipboard.writeText(text);
      }catch(_error){
        const area=document.createElement("textarea");
        area.value=text;area.style.position="fixed";area.style.opacity="0";
        document.body.appendChild(area);area.select();document.execCommand("copy");area.remove();
      }
      event.currentTarget.textContent="복사 완료";
      event.currentTarget.classList.add("app-dialog-copy-success");
    });
    document.getElementById("appDialogOverlay").addEventListener("click", event => {
      if(event.target.id === "appDialogOverlay") closeAppDialog(false);
    });
    document.addEventListener("keydown", event => {
      const overlay = document.getElementById("appDialogOverlay");
      if(event.key === "Escape" && overlay && !overlay.classList.contains("hidden")){
        closeAppDialog(false);
      }
    });
  }
  function isIpLike(str){
    return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(str.trim());
  }
  function statusBadge(status){
    const cls = status === "양호" ? "good" : "vuln";
    return `<span class="badge ${cls}"><span class="dot"></span>${status}</span>`;
  }
  function isGoodStatus(status){
    return ["양호", "O"].includes(String(status || "").trim().toUpperCase());
  }
  function rowsGoodFirst(rows){
    const order = status => status === "양호" || status === "O" ? 0 : 1;
    return [...rows].sort((left, right) => order(left.status) - order(right.status));
  }
  function actionTagBadge(tag){
    const cls = tag === "자동조치" ? "auto" : "approve";
    return `<span class="badge ${cls}"><span class="dot"></span>${tag}</span>`;
  }
  function sevTag(sev){
    const cls = SEV_CLASS[sev] || "low";
    return `<span class="sev ${cls}"><span class="sq"></span>${sev}</span>`;
  }
  function hostMeta(ip){ return hosts.find(h => h.ip === ip) || { hostname:"-", os_type:"-", domains:["UNIX"] }; }
  function enrich(r){ return Object.assign({}, r, itemMeta[r.code], { code:r.code }); }

  let activeDomainFilter = "ALL";

  function matchResultDomain(code){
    return activeDomainFilter === "ALL" || domainOfCode(code) === activeDomainFilter;
  }

  function filteredResults(){
    return results.filter(row => matchResultDomain(row.code));
  }

  function filteredHosts(){
    if(activeDomainFilter === "ALL") return hosts;
    const resultIps = new Set(filteredResults().map(row => row.ip));
    return hosts.filter(host => resultIps.has(host.ip));
  }

  function filteredCodes(){
    const presentCodes = new Set(filteredResults().map(row => row.code));
    return Object.keys(itemMeta).filter(code => matchResultDomain(code) && presentCodes.has(code));
  }

  function domainBoxes(domains){
    return (domains || ["UNIX"]).map(d => `<span class="domain-box ${DOMAIN_BOX_CLASS[d] || "domain-box-unix"}">${d}</span>`).join("");
  }

  function hostnameColumnWidth(hostRows){
    const widths = hostRows.map(host => Array.from(String(host.hostname || "-")).reduce(
      (sum, char) => sum + (char.codePointAt(0) > 0xff ? 2 : 1), 0
    ));
    return Math.max(8, Math.min(40, Math.max(...widths, 0))) + "ch";
  }

  function hostAndDomains(host){
    return '<span class="host-domain-layout"><span class="host-name">'
      + escapeHtml(host.hostname || "-")
      + '</span><span class="host-domains">'
      + domainBoxes(host.domains)
      + '</span></span>';
  }

  function showView(name){
    document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
    document.getElementById("view-" + name).classList.add("active");
    document.querySelectorAll(".nav-tab").forEach(t =>
      t.classList.toggle("active", t.dataset.view === name));
    document.getElementById("filterBar").classList.toggle("visible", name === "check" || name === "action");
    window.scrollTo({ top:0, behavior:"smooth" });
  }

  function activateSubtab(group, key){
    group.querySelectorAll(":scope > .subtabs > .subtab").forEach(b =>
      b.classList.toggle("active", b.dataset.subtab === key));
    group.querySelectorAll(":scope > .subview").forEach(v =>
      v.classList.toggle("active", v.dataset.subview === key));
  }

  function initTabGroups(){
    document.querySelectorAll(".tabgroup").forEach(group => {
      group.querySelectorAll(":scope > .subtabs > .subtab").forEach(btn => {
        btn.addEventListener("click", () => activateSubtab(group, btn.dataset.subtab));
      });
    });
  }

  function goToActionForIp(ip){
    showView("action");
    activateSubtab(document.querySelector('.tabgroup[data-tabgroup="action"]'), "byIp");
    const tr = document.querySelector(`#actionByIpBody tr[data-ip="${CSS.escape(ip)}"]`);
    if(tr){
      openIpDetail(ip, tr);
      tr.scrollIntoView({ behavior:"smooth", block:"center" });
    }
  }

  function goToActionForCode(code){
    showView("action");
    activateSubtab(document.querySelector('.tabgroup[data-tabgroup="action"]'), "byVuln");
    const tr = document.querySelector(`#actionByVulnBody tr[data-code="${CSS.escape(code)}"]`);
    if(tr){
      openVulnDetail(code, tr);
      tr.scrollIntoView({ behavior:"smooth", block:"center" });
    }
  }


  function normalizeSshFingerprint(value){
    const match=String(value || "").trim().match(/SHA256:[A-Za-z0-9+/]+={0,2}/);
    return match ? match[0].replace(/=+$/,"") : "";
  }

  function sshAuditResultLabel(result){
    return ({approved:"승인 완료",certificate_approved:"CA 인증 완료",deploy_failed:"인증서 배포 실패",verify_failed:"인증서 검증 실패",fingerprint_mismatch:"호스트 키 지문 불일치",observed_changed:"조회 키 변경",reauth_failed:"재인증 실패"})[result] || result;
  }

  function sshHostKeyFingerprintCommand(identity){
    const type=String((identity || {}).observed_type || "").toLowerCase();
    const keyFile=type.includes("rsa") ? "ssh_host_rsa_key.pub" : "ssh_host_ed25519_key.pub";
    return `sudo ssh-keygen -lf /etc/ssh/${keyFile} -E sha256`;
  }

  function renderSshAudit(rows){
    const list=document.getElementById("sshAuditList");
    document.getElementById("sshAuditSummary").textContent=rows.length ? `최근 ${rows.length}건` : "이력 없음";
    if(!rows.length){list.innerHTML='<p class="hint">아직 승인 이력이 없습니다.</p>';return;}
    list.innerHTML=rows.map(row=>`<div class="ssh-audit-item">
      <span>${escapeHtml(formatTimestamp((row.created_at || 0)*1000,true))}</span>
      <strong>${escapeHtml(row.approver || "-")}</strong>
      <span>${escapeHtml(sshAuditResultLabel(row.result))}<br><code>${escapeHtml(row.trusted_fp || row.observed_fp || "-")}</code></span>
    </div>`).join("");
  }

  async function loadSshAudit(ip){
    try{renderSshAudit(await API.getSshKeyAudit(ip));}
    catch(err){document.getElementById("sshAuditList").innerHTML=`<p class="hint">이력 조회 실패: ${escapeHtml(err.message)}</p>`;}
  }

  function updateSshApprovalMatch(){
    if(!sshApprovalRow) return;
    const trusted=normalizeSshFingerprint(document.getElementById("sshTrustedFingerprint").value);
    const password=document.getElementById("sshApprovalPassword").value;
    const status=document.getElementById("sshFingerprintMatch");
    status.classList.remove("is-match","is-mismatch");
    status.textContent=!trusted ? "직접 확인한 올바른 SHA256 SSH 호스트 키 지문을 입력하세요." : "입력한 지문은 화면에 노출되지 않은 네트워크 조회값과 서버에서 비교됩니다.";
    document.getElementById("sshApprovalConfirm").disabled=!(trusted && password);
  }

  function openSshApprovalModal(row){
    sshApprovalRow=row;
    document.getElementById("sshApprovalTarget").textContent=`${row.hostname} · ${row.ip}`;
    document.getElementById("sshFingerprintCommand").textContent=sshHostKeyFingerprintCommand(row.sshIdentity);
    const copyButton=document.getElementById("sshFingerprintCommandCopy");copyButton.textContent="명령어 복사";copyButton.classList.remove("app-dialog-copy-success");
    document.getElementById("sshTrustedFingerprint").value="";
    document.getElementById("sshApprovalPassword").value="";
    document.getElementById("sshApprovalState").textContent=row.sshIdentity.status==="changed" ? "키 변경 재승인" : "최초 신원 승인";
    document.getElementById("sshAuditList").innerHTML='<p class="hint">이력을 불러오는 중입니다.</p>';
    updateSshApprovalMatch();
    document.getElementById("sshApprovalModalOverlay").classList.remove("hidden");
    void loadSshAudit(row.ip);
    setTimeout(()=>document.getElementById("sshTrustedFingerprint").focus(),0);
  }

  function closeSshApprovalModal(){
    document.getElementById("sshApprovalModalOverlay").classList.add("hidden");sshApprovalRow=null;
  }

  function initSshApprovalModal(){
    const trusted=document.getElementById("sshTrustedFingerprint"),password=document.getElementById("sshApprovalPassword");
    trusted.addEventListener("input",updateSshApprovalMatch);password.addEventListener("input",updateSshApprovalMatch);
    document.getElementById("sshFingerprintCommandCopy").addEventListener("click",async event=>{
      const command=document.getElementById("sshFingerprintCommand").textContent;
      try{await navigator.clipboard.writeText(command);}
      catch(_error){
        const area=document.createElement("textarea");area.value=command;area.style.position="fixed";area.style.opacity="0";
        document.body.appendChild(area);area.select();document.execCommand("copy");area.remove();
      }
      event.currentTarget.textContent="복사 완료";event.currentTarget.classList.add("app-dialog-copy-success");
    });
    document.getElementById("sshApprovalCancel").addEventListener("click",closeSshApprovalModal);
    document.getElementById("sshApprovalModalOverlay").addEventListener("click",event=>{if(event.target.id==="sshApprovalModalOverlay")closeSshApprovalModal();});
    document.getElementById("sshApprovalConfirm").addEventListener("click",async event=>{
      if(!sshApprovalRow)return;
      const button=event.currentTarget;button.disabled=true;
      try{
        await API.approveSshKey(sshApprovalRow.ip,{
          trustedFingerprint:trusted.value,
          password:password.value
        });
        const ip=sshApprovalRow.ip;closeSshApprovalModal();
        await reloadHostsAndResults();renderIpTable();
        alert(`${ip} SSH 서버 신원을 승인했습니다. 승인 이력이 저장되었습니다.`);
      }catch(err){
        password.value="";updateSshApprovalMatch();await loadSshAudit(sshApprovalRow.ip);
        alert("SSH 신원 승인 실패: "+err.message);
      }
    });
  }

  const SSH_LABEL={unverified:"미확인",pending:"승인 대기",trusted:"승인됨",certified:"CA 인증",changed:"키 변경"};
  const CONNECT_LABEL={unknown:"미확인",connected:"연결됨",ready:"준비 완료",unreachable:"연결 실패",blocked:"차단됨"};
  function stateClass(s){return ["trusted","certified","valid","connected","ready"].includes(s)?"security-ok":(["pending","unknown","unverified","none"].includes(s)?"security-warn":"security-bad");}

  const CHECK_LABEL={
    ssh_identity:"SSH 신원 승인",
    ssh_auth:"SSH 인증",
    os_support:"OS 지원 여부",
    sudo_nopasswd:"sudo 비대화형 권한",
    job_conflict:"다른 작업과 충돌 없음"
  };

  function checkPillHtml(check){
    const status=check.status || (check.ok ? "ok" : "fail");
    const cls=status==="ok" ? "security-ok" : (status==="skip" ? "security-warn" : "security-bad");
    const label=status==="ok" ? "통과" : (status==="skip" ? "건너뜀" : "실패");
    return `<span class="info-check-pill ${cls}">${label}</span>`;
  }

  async function showCaCertificateInfo(row){
    const identity=row.sshIdentity || {};
    const certified=identity.status==="certified";
    let audit=[];
    try{ audit=await API.getSshKeyAudit(row.ip); }catch(_error){ audit=[]; }
    const events=audit.filter(a=>a.action==="cert_deploy" || a.action==="bootstrap").slice(0,4);
    const steps=[
      { label:"Host CA 준비", detail:"관리자가 상단에서 ed25519 SSH Host CA 키쌍을 1회 생성(ssh-keygen -t ed25519)해 모든 서버가 공유하는 신뢰 루트를 마련했습니다.", done:true },
      { label:"기존 지문 방식 승인", detail: identity.approved_at ? `콘솔에서 직접 확인한 SSH 호스트 키 지문을 네트워크 조회 결과와 대사해 ${formatLogTimestamp(identity.approved_at*1000)}에 최초 승인했습니다.` : "콘솔에서 직접 확인한 SSH 호스트 키 지문을 네트워크 조회 결과와 대사해 최초 승인했습니다.", done:Boolean(identity.approved_at) },
      { label:"CA 서명 인증서 발급·배포", detail:"승인된 호스트 키에 ssh-keygen -s로 CA 서명을 붙이고(-h -n hostname,ip 로 principal 고정, 유효기간 1년), 관리자 재인증 후 SSH로 원격 sshd에 설치했습니다.", done:certified },
      { label:"sshd 설정 반영 검증", detail:"원격에서 sshd_config를 백업한 뒤 sshd -t 문법 검사와 서비스 reload가 모두 성공한 경우에만 적용을 확정하고, 실패 시 자동으로 백업본으로 되돌립니다.", done:certified },
      { label:"네트워크 재검증", detail: identity.scanned_at ? `배포 후 ssh-keyscan으로 다시 조회해 CA 서명 인증서를 확인하고 ${formatLogTimestamp(identity.scanned_at*1000)}에 'CA 인증' 상태로 전환했습니다.` : "배포 후 ssh-keyscan으로 다시 조회해 CA 서명 인증서가 실제로 적용됐는지 확인했습니다.", done:certified },
    ];
    const stepsHtml=steps.map((step,index)=>`
      <li class="info-step ${step.done ? "" : "is-pending"}">
        <span class="info-step-num">${step.done ? (index+1) : "·"}</span>
        <span class="info-step-body"><strong>${escapeHtml(step.label)}</strong><span>${escapeHtml(step.detail)}</span></span>
      </li>`).join("");
    const auditHtml=events.length ? `<div class="modal-section-label" style="margin-top:14px">감사 이력</div><ul class="info-audit-list">${events.map(a=>`<li>${escapeHtml(formatLogTimestamp(a.created_at*1000))} · ${escapeHtml(a.action)} → ${escapeHtml(a.result)}${a.approver ? ` (${escapeHtml(a.approver)})` : ""}</li>`).join("")}</ul>` : "";
    const intro=certified
      ? `${escapeHtml(row.hostname || row.ip)}는 SSH Host CA가 서명한 인증서로 신원이 확인되어, 이후 개별 지문 재승인 없이 인증서의 CA 서명과 호스트명/IP principal만으로 자동 신뢰됩니다.`
      : `${escapeHtml(row.hostname || row.ip)}는 아직 CA 인증서가 배포되지 않았습니다. 'CA 인증됨'이 되기까지 아래 절차를 거칩니다.`;
    const html=`
      <div class="info-tech-badge">OpenSSH SSH Certificates</div>
      <div class="info-tech-badge">ssh-keygen CA (ed25519)</div>
      <div class="info-tech-badge">Principal 고정: hostname · IP</div>
      <p style="margin:10px 0 0">${intro}</p>
      <ol class="info-steps">${stepsHtml}</ol>
      ${identity.certificate_fp ? `<div class="info-fp">인증서 지문 ${escapeHtml(identity.certificate_fp)}</div>` : ""}
      ${auditHtml}
    `;
    await openAppDialog(html, { title:`${row.ip} · SSH Host CA 인증 상세`, html:true, wide:true });
  }

  async function showConnectionReadyInfo(row){
    const connection=row.connectionStatus || {};
    const preflight=connection.preflight;
    const hostResult=preflight && Array.isArray(preflight.hosts) ? preflight.hosts.find(host=>host.ip===row.ip) : null;
    const checks=hostResult ? (hostResult.checks || []) : [];
    const checksHtml=checks.length
      ? `<ul class="info-checks">${checks.map(check=>`
          <li class="info-check-row">
            ${checkPillHtml(check)}
            <span class="info-check-name">${escapeHtml(CHECK_LABEL[check.name] || check.name)}</span>
            <span class="info-check-detail">${escapeHtml(check.detail || "")}</span>
          </li>`).join("")}</ul>`
      : `<p style="margin-top:10px;color:var(--text-2)">최근 사전점검 상세 기록이 없습니다. 상단에서 사전점검을 다시 실행하면 항목별 결과를 확인할 수 있습니다.</p>`;
    const html=`
      <div class="info-tech-badge">SSH BatchMode 접속</div>
      <div class="info-tech-badge">/etc/os-release 조회</div>
      <div class="info-tech-badge">sudo -n 무중단 권한 확인</div>
      <p style="margin:10px 0 0">'${escapeHtml(CONNECT_LABEL[connection.status] || connection.status)}' 상태는 아래 항목을 순서대로 점검해 모두 통과했을 때만 표시됩니다. 하나라도 실패하면 '차단됨'으로 표시되며 원격 작업이 실행되지 않습니다.</p>
      ${checksHtml}
      ${connection.checked_at ? `<p style="margin-top:12px;color:var(--text-2);font-size:12px">마지막 점검 ${escapeHtml(formatLogTimestamp(connection.checked_at*1000))}${connection.latency_ms!=null ? ` · 지연 ${connection.latency_ms}ms` : ""}</p>` : ""}
    `;
    await openAppDialog(html, { title:`${row.ip} · 접속 준비 상태 상세`, html:true, wide:true });
  }
  function updateEvidenceButton(){document.querySelectorAll(".latest-evidence-btn").forEach(b=>{b.disabled=!latestEvidenceJob;b.title=latestEvidenceJob ? `작업 ${latestEvidenceJob.id} 증적` : "생성된 증적 없음";});}

  function caActionButtonHtml(row){
    if(row.sshIdentity.status==="changed"){
      return `<button class="btn btn-danger btn-small" data-ca-action="approve" data-info-ip="${escapeHtml(row.ip)}">키 변경 · 재승인</button>`;
    }
    return "";
  }
  async function hostSecurityAction(row,action,button){
    button.disabled=true;
    try{
      if(action==="scan"){
        const identity=await API.scanSshKey(row.ip);
        row.sshIdentity=identity;
        if(["pending","changed"].includes(identity.status)){
          openSshApprovalModal(row);
          return;
        }
        alert("현재 SSH 호스트 키가 승인된 키와 일치합니다.");
      }
      else if(action==="approve"){
        if(!["pending","changed"].includes(row.sshIdentity.status)){
          row.sshIdentity=await API.scanSshKey(row.ip);
        }
        if(!["pending","changed"].includes(row.sshIdentity.status)){
          throw new Error("현재 SSH 호스트 키는 이미 승인되어 있습니다.");
        }
        openSshApprovalModal(row);return;
      }
      else if(action==="connection"){const v=await API.checkConnection(row.ip);alert(`접속 상태: ${CONNECT_LABEL[v.status]||v.status}\n${v.detail||""}`);}
      else{
        const v=await API.preflightHosts([row.ip]),h=v.hosts[0];
        const guidance=preflightFixGuidance(v);
        const message=`사전점검 ${h.ok?"통과":"실패"}\n\n${h.checks.map(x=>`${String(x.status || (x.ok?"ok":"fail")).toUpperCase()} · ${x.name}: ${x.detail}`).join("\n")}`+
          (guidance.length ? `\n\n--- 해결 방법 ---\n${guidance.join("\n")}` : "");
        if(h.ok) alert(message); else alertWithCommands(message,preflightFixCommands(v));
      }
      await reloadHostsAndResults();renderIpTable();
    }catch(err){alert("보안 확인 실패: "+err.message);}finally{button.disabled=false;}
  }

  function initSshCaControls(){
    document.getElementById("sshCaDeployAllBtn").addEventListener("click",deployAllSshCertificates);
    document.getElementById("connectionCheckAllBtn").addEventListener("click",checkAllConnections);
  }

  async function deployAllSshCertificates(){
    const changed=registeredIps.filter(row=>row.sshIdentity.status==="changed");
    const targets=registeredIps.filter(row=>row.sshIdentity.status!=="certified" && row.sshIdentity.status!=="changed");
    if(!targets.length){
      alert(changed.length
        ? "키가 변경되어 재승인이 필요한 서버만 남아있습니다. 해당 행의 '키 변경 · 재승인' 버튼을 사용하세요."
        : "인증할 서버가 없습니다.");
      return;
    }
    const overlay=document.getElementById("sshCaDeployModalOverlay");
    const start=document.getElementById("sshCaDeployStartBtn");
    const closeBtn=document.getElementById("sshCaDeployCloseBtn");
    const passwordInput=document.getElementById("sshCaDeployPassword");
    const progress=document.getElementById("sshCaDeployProgress");
    const caNote=sshCaState.ready ? "" : " (Host CA 초기화 포함)";
    document.getElementById("sshCaDeploySummary").textContent=`대상 ${targets.length}대를 SSH Host CA로 인증합니다${caNote}.`;
    progress.textContent="";passwordInput.value="";overlay.classList.remove("hidden");passwordInput.focus();

    const password=await new Promise(resolve=>{
      start.onclick=()=>{if(!passwordInput.value)return;resolve(passwordInput.value);};
      closeBtn.onclick=()=>resolve(null);
    });
    if(password===null){overlay.classList.add("hidden");return;}

    start.disabled=true;closeBtn.disabled=true;passwordInput.disabled=true;
    const button=document.getElementById("sshCaDeployAllBtn");button.disabled=true;
    const succeeded=[];const failed=[];
    try{
      if(!sshCaState.ready){
        progress.textContent="Host CA 초기화 중...";
        sshCaState=await API.initializeSshCa(password);
      }
      for(const row of targets){
        progress.textContent=`${row.ip}(${row.hostname || "미확인"}) 인증 중... (${succeeded.length+failed.length+1}/${targets.length})`;
        try{await API.deploySshCertificate(row.ip,password);succeeded.push(row.ip);}
        catch(error){failed.push(`${row.ip}: ${error.message}`);}
      }
      await reloadHostsAndResults();renderIpTable();
      overlay.classList.add("hidden");
      let message=`성공 ${succeeded.length}대 · 실패 ${failed.length}대`;
      if(failed.length)message+="\n\n"+failed.join("\n");
      if(changed.length)message+=`\n\n키 변경으로 건너뜀(재승인 필요): ${changed.map(row=>row.ip).join(", ")}`;
      await openAppDialog(message,{title:"전체 서버 인증 결과"});
    }catch(error){
      overlay.classList.add("hidden");
      await openAppDialog("Host CA 초기화 실패: "+error.message,{title:"전체 서버 인증 결과"});
    }finally{
      start.disabled=false;closeBtn.disabled=false;passwordInput.disabled=false;
      button.disabled=false;
    }
  }

  async function checkAllConnections(){
    const button=document.getElementById("connectionCheckAllBtn");button.disabled=true;
    try{
      const results=await Promise.all(registeredIps.map(async row=>{
        try{return await API.checkConnection(row.ip);}
        catch(error){return {status:"unreachable",detail:error.message};}
      }));
      await reloadHostsAndResults();renderIpTable();
      const connected=results.filter(item=>item.status==="connected").length;
      alert(`전체 연결 확인 완료: ${connected}/${results.length}대 연결됨`);
    }finally{button.disabled=false;}
  }


  function renderIpTable(){
    const body = document.getElementById("ipTableBody");
    document.getElementById("ipCount").textContent = `(총 ${registeredIps.length}건)`;

    if(registeredIps.length === 0){
      body.innerHTML = `<tr class="empty-row"><td colspan="8">등록된 IP가 없습니다. 위에서 IP를 등록해 주세요.</td></tr>`;
      updateBulkActionUI();
      return;
    }
    body.innerHTML = registeredIps.map((row, idx) => `
      <tr class="ip-select-row">
        <td><input type="checkbox" class="ip-select" data-ip="${escapeHtml(row.ip)}" ${selectedIps.has(row.ip) ? "checked" : ""} /></td>
        <td class="mono registered-ip-cell"><div class="ip-select-target" data-ip="${escapeHtml(row.ip)}">${escapeHtml(row.ip)}</div></td>
        <td>${escapeHtml(row.hostname || "미확인")}</td>
        <td>${domainBoxes(row.domains || ["UNIX"])}</td>
        <td class="ca-cell">
          <span class="state-btn ${stateClass(row.sshIdentity.status)}" data-info="ca" data-info-ip="${escapeHtml(row.ip)}" title="자세히 보기">${escapeHtml(SSH_LABEL[row.sshIdentity.status] || row.sshIdentity.status)}</span>
          ${caActionButtonHtml(row)}
        </td>
        <td><span class="state-btn ${stateClass(row.connectionStatus.status)}" data-info="conn" data-info-ip="${escapeHtml(row.ip)}" title="${escapeHtml(row.connectionStatus.detail || "")} · 자세히 보기">${escapeHtml(CONNECT_LABEL[row.connectionStatus.status] || row.connectionStatus.status)}</span></td>
        <td class="col-detail mono">${escapeHtml(formatLogTimestamp(row.registeredAt))}</td>
        <td><button class="btn btn-danger" data-remove-idx="${idx}">삭제</button></td>
      </tr>`).join("");

    body.querySelectorAll(".ip-select").forEach(cb => {
      cb.addEventListener("change", () => {
        if(cb.checked) selectedIps.add(cb.dataset.ip);
        else selectedIps.delete(cb.dataset.ip);
        updateBulkActionUI();
      });
    });
    body.querySelectorAll(".ip-select-row").forEach(row => {
      row.addEventListener("click", event => {
        if(event.target.closest("input,button,a,select,textarea,[data-info]"))return;
        const checkbox = row.querySelector(".ip-select");
        if(!checkbox)return;
        checkbox.checked = !checkbox.checked;
        checkbox.dispatchEvent(new Event("change", {bubbles:true}));
      });
    });

    body.querySelectorAll("[data-info='ca']").forEach(span => {
      span.addEventListener("click", event => {
        event.stopPropagation();
        const row = registeredIps.find(item => item.ip === span.dataset.infoIp);
        if(row) void showCaCertificateInfo(row);
      });
    });
    body.querySelectorAll("[data-info='conn']").forEach(span => {
      span.addEventListener("click", event => {
        event.stopPropagation();
        const row = registeredIps.find(item => item.ip === span.dataset.infoIp);
        if(row) void showConnectionReadyInfo(row);
      });
    });

    body.querySelectorAll("[data-ca-action]").forEach(btn => {
      btn.addEventListener("click", event => {
        event.stopPropagation();
        const row = registeredIps.find(item => item.ip === btn.dataset.infoIp);
        if(row) void hostSecurityAction(row, btn.dataset.caAction, btn);
      });
    });

    body.querySelectorAll("[data-remove-idx]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const removed = registeredIps[Number(btn.dataset.removeIdx)];
        btn.disabled = true;
        try{
          await API.removeHost(removed.ip);
          selectedIps.delete(removed.ip);
          await reloadHostsAndResults();
          renderAll();
        }catch(err){
          alert("삭제 요청 실패: " + err.message);
          btn.disabled = false;
        }
      });
    });

    updateBulkActionUI();
  }

  function updateBulkActionUI(){
    const btn = document.getElementById("bulkCheckRemediateBtn");
    const countEl = document.getElementById("selectedCount");
    const selectAllCb = document.getElementById("selectAllIps");
    const n = selectedIps.size;
    const total = registeredIps.length;

    btn.disabled = n === 0;
    countEl.textContent = n > 0 ? `${n}건 선택됨` : "";

    selectAllCb.checked = total > 0 && n === total;
    selectAllCb.indeterminate = n > 0 && n < total;
  }

  function itemKey(ip, code){ return ip + "|" + code; }

  function allEligibleKeys(){
    return filteredResults()
      .filter(r => r.status === "취약" && itemMeta[r.code].action_tag === "승인요청")
      .map(r => itemKey(r.ip, r.code));
  }

  function setFilters(domain){
    activeDomainFilter = domain;
    document.querySelectorAll("#domainFilterGroup .seg-btn").forEach(b => b.classList.toggle("active", b.dataset.domain === activeDomainFilter));
    renderCheckView();
    renderSecurityScore();
    renderActionByIp();
    renderActionByVuln();
    renderNavStats();
  }

  const GRADE_CSS_CLASS = {
    "우수":"grade-good", "양호":"grade-good",
    "보통":"grade-normal",
    "미흡":"grade-poor",
    "취약":"grade-critical"
  };

  function securityGrade(score){
    if(score === null) return { emoji:"⚪", label:"평가 불가" };
    if(score >= 91) return { emoji:"🟢", label:"우수" };
    if(score >= 81) return { emoji:"🟢", label:"양호" };
    if(score >= 71) return { emoji:"🟡", label:"보통" };
    if(score >= 61) return { emoji:"🟠", label:"미흡" };
    return { emoji:"🔴", label:"취약" };
  }

  function securityScoreForIp(ip){
    const rows = filteredResults().filter(r => r.ip === ip);
    let maxScore = 0;
    let deduction = 0;

    rows.forEach(r => {
      const severity = itemMeta[r.code] && itemMeta[r.code].severity;
      const weight = SECURITY_SEV_WEIGHT[severity] || 0;
      if(weight === 0) return;
      maxScore += weight;
      if(["양호", "O", "o"].includes(r.status)) return;
      if(["일부조치", "부분양호", "P", "p"].includes(r.status)) deduction += weight * 0.5;
      else deduction += weight;
    });

    return {
      score: maxScore > 0 ? Math.round(((maxScore - deduction) / maxScore) * 10000) / 100 : null,
      itemCount: rows.length,
      vulnCount: rows.filter(r => r.status !== "양호" && r.status !== "O" && r.status !== "o").length
    };
  }

  function formatSecurityScore(score){
    return score === null ? "-" : Number(score.toFixed(1)).toString();
  }

  function renderSecurityScore(){
    const cards = document.querySelectorAll("[data-security-score]");
    if(cards.length === 0) return;

    const ipScores = filteredHosts().map(host => ({ host, ...securityScoreForIp(host.ip) }));
    const scored = ipScores.filter(item => item.score !== null);
    const average = scored.length
      ? Math.round((scored.reduce((sum, item) => sum + item.score, 0) / scored.length) * 100) / 100
      : null;
    const averageGrade = securityGrade(average);

    cards.forEach(card => {
      const numEl = card.querySelector("[data-score-overall-num]");
      const gradeEl = card.querySelector("[data-score-overall-grade]");
      const gridEl = card.querySelector("[data-score-ip-grid]");

      const overallEl = card.querySelector(".score-overall");
      numEl.textContent = average === null ? "-" : formatSecurityScore(average) + "점";
      gradeEl.textContent = `${averageGrade.emoji} ${averageGrade.label}`;
      gradeEl.className = "score-overall-grade " + (GRADE_CSS_CLASS[averageGrade.label] || "");
      if(overallEl) overallEl.className = "score-overall " + (GRADE_CSS_CLASS[averageGrade.label] || "");

      const scoredItems = ipScores.filter(item => item.score !== null);
      if(scoredItems.length === 0){
        gridEl.innerHTML = `<p class="hint">보안 점수가 산정된 IP가 없습니다.</p>`;
        return;
      }

      gridEl.innerHTML = scoredItems.map(({ host, score, itemCount, vulnCount }) => {
        const grade = securityGrade(score);
        return `<div class="score-domain-item clickable" data-score-ip="${escapeHtml(host.ip)}" tabindex="0" role="button" aria-label="${escapeHtml(host.ip)} IP별 상세 현황 열기">
        <div class="score-ip-item-head">
          <div class="score-domain-item-label mono">${escapeHtml(host.ip)}</div>
          <span class="score-ip-grade ${GRADE_CSS_CLASS[grade.label] || ""}">${grade.emoji} ${grade.label}</span>
        </div>
        <div class="score-domain-item-num">${formatSecurityScore(score)}점</div>
        <div class="score-domain-item-sub">${escapeHtml(host.hostname)} · 점검 ${itemCount}건 · 취약 ${vulnCount}건</div>
      </div>`;
      }).join("");

      gridEl.querySelectorAll("[data-score-ip]").forEach(item => {
        const open = () => goToActionForIp(item.dataset.scoreIp);
        item.addEventListener("click", open);
        item.addEventListener("keydown", event => {
          if(event.key === "Enter" || event.key === " "){
            event.preventDefault();
            open();
          }
        });
      });
    });
  }

  function renderNavStats(){
    const el = document.getElementById("navStats");
    if(!el) return;
    if(!currentUser || hosts.length === 0){ el.innerHTML = ""; return; }
    const scores = filteredHosts().map(h => securityScoreForIp(h.ip).score).filter(s => s !== null);
    const average = scores.length ? Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length) : null;
    el.innerHTML = `
      <span class="nav-stat"><span class="nav-stat-l">등록 서버</span><span class="nav-stat-v">${filteredHosts().length}<em>대</em></span></span>
      <span class="nav-stat score"><span class="nav-stat-l">평균 점수</span><span class="nav-stat-v">${average === null ? "-" : `${average}<em>점</em>`}</span></span>`;
  }

  function notificationSeenId(){
    try{ return Number(localStorage.getItem("ssapCheckNoticeSeenId") || 0); }
    catch(_error){ return 0; }
  }

  function markNotificationsRead(){
    const newestId = checkRuns.reduce((maxId, run) => Math.max(maxId, Number(run.id) || 0), 0);
    try{ localStorage.setItem("ssapCheckNoticeSeenId", String(newestId)); }
    catch(_error){  }
    const errors = loadErrorNotifications().map(item => Object.assign({}, item, { read:true }));
    saveErrorNotifications(errors);
    renderCheckNotifications();
  }

  function renderCheckNotifications(){
    const list = document.getElementById("checkNoticeList");
    const badge = document.getElementById("checkNoticeBadge");
    const summary = document.getElementById("checkNoticeSummary");
    if(!list || !badge || !summary) return;

    const errors = loadErrorNotifications();
    const unseenChecks = checkRuns.filter(run => (Number(run.id) || 0) > notificationSeenId()).length;
    const unseen = unseenChecks + errors.filter(item => !item.read).length;
    badge.textContent = unseen > 99 ? "99+" : String(unseen);
    badge.classList.toggle("hidden", unseen === 0);
    const notices = [
      ...checkRuns.map(run => ({ type:"check", created_at:run.created_at, data:run })),
      ...errors.map(error => ({ type:"error", created_at:error.created_at, data:error }))
    ].sort((left, right) => logTimeNumber(right.created_at) - logTimeNumber(left.created_at)).slice(0, 10);
    summary.textContent = notices.length ? `최근 ${notices.length}건` : "알림 없음";

    if(notices.length === 0){
      list.innerHTML = `<div class="nav-notice-empty">아직 점검 알림이 없습니다.</div>`;
      return;
    }
    list.innerHTML = notices.map(notice => {
      if(notice.type === "error"){
        const error = notice.data;
        const firstLine = String(error.message || "오류가 발생했습니다.").split("\n")[0];
        return `<button type="button" class="nav-notice-item is-error" data-error-notice-id="${escapeHtml(error.id)}">
          <span class="nav-notice-dot"></span>
          <span class="nav-notice-main">오류 알림</span>
          <span class="nav-notice-time">${escapeHtml(formatLogTimestamp(error.created_at))}</span>
          <span class="nav-notice-detail">${escapeHtml(firstLine)}</span>
        </button>`;
      }
      const run = notice.data;
      return `<div class="nav-notice-item">
          <span class="nav-notice-dot"></span>
          <span class="nav-notice-main">${escapeHtml(run.host || "-")} · ${escapeHtml(run.domain || "-")} · ${escapeHtml(run.run_kind || "점검")}</span>
          <span class="nav-notice-time">${escapeHtml(formatLogTimestamp(run.created_at))}</span>
          <span class="nav-notice-detail">
            <span>총 ${Number(run.total_count) || 0}건</span>
            <span class="good">양호 ${Number(run.good_count) || 0}</span>
            <span class="vuln">취약 ${Number(run.vuln_count) || 0}</span>
          </span>
        </div>`;
    }).join("");
    list.querySelectorAll("[data-error-notice-id]").forEach(button => {
      button.addEventListener("click", () => {
        const error = loadErrorNotifications().find(item => item.id === button.dataset.errorNoticeId);
        if(!error) return;
        document.getElementById("checkNoticePopover").classList.add("hidden");
        document.getElementById("checkNoticeBtn").setAttribute("aria-expanded", "false");
        void openAppDialog(error.message, { title:"오류 알림" });
      });
    });
  }

  function initCheckNotifications(){
    const wrap = document.querySelector(".nav-notice-wrap");
    const button = document.getElementById("checkNoticeBtn");
    const popover = document.getElementById("checkNoticePopover");
    button.addEventListener("click", event => {
      event.stopPropagation();
      const willOpen = popover.classList.contains("hidden");
      popover.classList.toggle("hidden", !willOpen);
      button.setAttribute("aria-expanded", String(willOpen));
      if(willOpen) markNotificationsRead();
    });
    document.addEventListener("click", event => {
      if(!event.target.closest(".nav-notice-wrap")){
        popover.classList.add("hidden");
        button.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", event => {
      if(event.key === "Escape"){
        popover.classList.add("hidden");
        button.setAttribute("aria-expanded", "false");
      }
    });
    if(wrap) renderCheckNotifications();
  }

  function domainVulnerabilityCategories(domain){
    if(domain === "UNIX"){
      return [
        { label:"계정 관리", match:number => number >= 1 && number <= 13 },
        { label:"파일/디렉토리 관리", match:number => number >= 14 && number <= 33 },
        { label:"서비스 관리", match:number => number >= 34 && number <= 63 },
        { label:"패치 관리", match:number => number === 64 },
        { label:"로그 관리", match:number => number >= 65 && number <= 67 }
      ];
    }
    if(domain === "WEB"){
      return [
        { label:"계정 관리", match:number => number >= 1 && number <= 3 },
        { label:"서비스 관리", match:number => number >= 4 && number <= 24 },
        { label:"패치 관리", match:number => number === 25 },
        { label:"로그 관리", match:number => number >= 26 }
      ];
    }
    return [
      { label:"계정/권한 관리", match:number => number >= 1 && number <= 8 },
      { label:"접근/옵션 관리", match:number => number >= 9 && number <= 24 },
      { label:"패치 관리", match:number => number === 25 },
      { label:"로그 관리", match:number => number >= 26 }
    ];
  }

  function renderDomainSummary(){
    const container = document.getElementById("domainSummary");
    if(!container) return;
    const domains = [
      { key:"UNIX", cls:"domain-card-unix" },
      { key:"WEB",  cls:"domain-card-web"  },
      { key:"DBMS", cls:"domain-card-dbms" },
    ];

    const totalsEl = document.getElementById("domainTotals");
    if(totalsEl){
      const total = results.length;
      const vulnAll = results.filter(r => r.status === "취약").length;
      const goodAll = results.filter(r => isGoodStatus(r.status)).length;
      const goodRate = total ? Math.round((goodAll / total) * 1000) / 10 : 0;
      const pendingAll = results.filter(r => r.status === "취약" && (itemMeta[r.code] || {}).action_tag === "승인요청").length;
      const autoAll = vulnAll - pendingAll;
      const affectedHosts = new Set(results.filter(r => r.status === "취약").map(r => r.ip)).size;
      totalsEl.innerHTML = `
        <div class="dt-item"><span class="dt-l">전체 점검 항목</span><span class="dt-v">${total}<em>건</em></span><span class="dt-sub">서버 ${hosts.length}대 기준</span></div>
        <div class="dt-item vuln"><span class="dt-l">취약 항목</span><span class="dt-v">${vulnAll}<em>건</em></span><span class="dt-sub">영향 서버 ${affectedHosts}대</span></div>
        <div class="dt-item appr"><span class="dt-l">승인 필요 / 자동조치</span><span class="dt-v">${pendingAll}<em>건</em></span><span class="dt-sub">자동조치 가능 ${autoAll}건</span></div>
        <div class="dt-item good"><span class="dt-l">양호율</span><span class="dt-v">${goodRate}<em>%</em></span><span class="dt-track"><span style="width:${goodRate}%"></span></span></div>`;
    }

    container.innerHTML = domains.map(({ key, cls }) => {
      const rows = results.filter(row => domainOfCode(row.code) === key);
      const vulnRows = rows.filter(r => r.status === "취약");
      const vuln = vulnRows.length;
      const rate = rows.length ? Math.round((vuln / rows.length) * 1000) / 10 : 0;

      const categoryDefinitions = domainVulnerabilityCategories(key);
      const categories = categoryDefinitions.map(category => ({
        label:category.label,
        count:vulnRows.filter(row => {
          const number = Number((String(row.code || "").match(/(\d+)$/) || [])[1]) || 0;
          return category.match(number);
        }).length
      }));
      const categoryMax = Math.max(...categories.map(category => category.count), 1);
      const categoryChart = categories.map(category => {
        const width = category.count ? Math.max(8, (category.count / categoryMax) * 100) : 0;
        return '<span class="domain-rank-row">'
          + '<span class="domain-rank-label">' + escapeHtml(category.label) + '</span>'
          + '<span class="domain-rank-track"><span class="domain-rank-fill" style="width:' + width + '%"></span></span>'
          + '<b class="domain-rank-count">' + category.count + '</b>'
          + '</span>';
      }).join("");
      const categoryAria = categories.map(category => category.label + " " + category.count + "건").join(", ");

      const approve = vulnRows.filter(r => (itemMeta[r.code] || {}).action_tag === "승인요청").length;
      const auto = vuln - approve;
      const domainHosts = new Set(rows.map(r => r.ip)).size;
      const affected = new Set(vulnRows.map(r => r.ip)).size;
      const isActive = activeDomainFilter === key;
      const clean = vuln === 0;

      return `<button type="button" class="domain-card ${cls} ${isActive ? "active-card" : ""}" data-domain="${key}">
        <span class="domain-card-top">
          <span class="domain-card-label">${key}</span>
          <span class="domain-card-hosts ${clean ? "zero" : ""}">서버 <b>${affected}</b>/${domainHosts}대 영향</span>
        </span>
        <span class="domain-card-n ${clean ? "zero" : ""}">${vuln}<small>건 취약</small></span>
        <span class="domain-card-rateline ${clean ? "zero" : ""}">전체 ${rows.length}건 중 취약률 <b>${rate}%</b></span>
        <span class="domain-rank-chart" role="img" aria-label="${key} 진단 영역별 취약 분포 — ${categoryAria}">${categoryChart}</span>
        <span class="domain-card-foot">
          ${clean
            ? `<span class="dc-chip clear">조치 완료 — 취약 없음</span>`
            : `<span class="dc-chip approve">승인 필요 <b>${approve}</b>건</span><span class="dc-chip auto">자동조치 <b>${auto}</b>건</span>`}
        </span>
      </button>`;
    }).join("");

    container.querySelectorAll(".domain-card").forEach(btn => {
      btn.addEventListener("click", () => setFilters(btn.dataset.domain));
    });
  }

  function renderRemediationUpdates(){
    const card = document.getElementById("checkUpdateCard");
    const timeEl = document.getElementById("checkUpdateTime");
    const summaryEl = document.getElementById("checkUpdateSummary");
    const listEl = document.getElementById("checkUpdateList");
    if(!card || !timeEl || !summaryEl || !listEl) return;

    if(remediationUpdates.length === 0){
      timeEl.textContent = "업데이트 대기";
      summaryEl.textContent = "자동조치 또는 승인조치 후 변경 결과가 여기에 표시됩니다.";
      listEl.innerHTML = `<div class="check-update-empty">아직 조치 업데이트 내역이 없습니다.</div>`;
      card.classList.remove("hidden");
      return;
    }

    const fixed = remediationUpdates.filter(item => item.outcome === "fixed").length;
    const alreadyGood = remediationUpdates.filter(item => item.outcome === "already_good").length;
    const unresolved = remediationUpdates.length - fixed - alreadyGood;
    timeEl.textContent = remediationUpdateTime || "";
    const scoreText = remediationScoreChange && remediationScoreChange.initial !== null && remediationScoreChange.final !== null
      ? ` · 초기 ${formatSecurityScore(remediationScoreChange.initial)}점 → 조치 후 ${formatSecurityScore(remediationScoreChange.final)}점`
      : "";
    summaryEl.innerHTML = `총 ${remediationUpdates.length}건 · <span class="update-summary-good">양호 전환 ${fixed}건</span> · 변화 없음 ${alreadyGood}건 · <span class="update-summary-bad">미조치/실패 ${unresolved}건</span>${scoreText}`;
    listEl.innerHTML = remediationUpdates.map(item => {
      const outcome = {
        fixed: { label:"양호 전환", cls:"fixed" },
        already_good: { label:"변화 없음", cls:"unchanged" },
        unchanged: { label:"미조치", cls:"unchanged" },
        failed: { label:"실행 실패", cls:"failed" },
        unknown: { label:"결과 확인 불가", cls:"unknown" }
      }[item.outcome];
      return `<div class="check-update-item ${outcome.cls}">
        <div class="check-update-main">
          <span class="check-update-outcome">${escapeHtml(item.source || "승인조치")} · ${outcome.label}</span>
          <span class="mono">${escapeHtml(item.ip)}</span>
          <span class="mono">${escapeHtml(item.code)}</span>
          <span class="check-update-title">${escapeHtml(item.title || "-")}</span>
        </div>
        <div class="check-update-detail">${escapeHtml(item.before)} → ${escapeHtml(item.after)}${item.detail ? ` · ${escapeHtml(item.detail)}` : ""}</div>
      </div>`;
    }).join("");
    card.classList.remove("hidden");
  }

  function recordRemediationUpdates(items, beforeByKey, job, requestError){
    remediationUpdateTime = formatLogTimestamp(new Date().toISOString());
    remediationScoreChange = null;
    remediationUpdates = items.map(item => {
      const key = itemKey(item.ip, item.code);
      const before = beforeByKey.get(key) || { status:"취약", title:(itemMeta[item.code] || {}).title };
      const afterRow = results.find(r => r.ip === item.ip && r.code === item.code);
      const afterStatus = afterRow ? afterRow.status : "결과 없음";
      let outcome = "unknown";
      let detail = requestError || (job && job.error) || "";

      if(requestError || (job && job.status !== "success")) outcome = "failed";
      else if(!isGoodStatus(before.status) && isGoodStatus(afterStatus)) outcome = "fixed";
      else if(isGoodStatus(before.status) && isGoodStatus(afterStatus)) outcome = "already_good";
      else if(afterRow) outcome = "unchanged";

      if(outcome === "unchanged" && afterRow && afterRow.detail) detail = afterRow.detail;
      return {
        ip:item.ip,
        code:item.code,
        title:before.title || (itemMeta[item.code] || {}).title,
        before:before.status,
        after:afterStatus,
        outcome,
        detail,
        source:"승인조치"
      };
    });
  }

  function renderCheckView(){
    renderDomainSummary();
    renderRemediationUpdates();
    renderCheckByIpGroups();
    renderCheckByVulnGroups();
    updateCheckApproveUI();
  }

  function renderCheckByIpGroups(){
    const container = document.getElementById("checkByIpGroups");
    const visibleHosts = filteredHosts();
    container.style.setProperty("--host-name-width", hostnameColumnWidth(visibleHosts));
    const hostRows = visibleHosts.map(host => ({
      host,
      latestCheck:latestCheckTimeForIp(host.ip)
    })).sort((left, right) => (
      logTimeNumber(right.latestCheck) - logTimeNumber(left.latestCheck)
      || compareIpAddresses(left.host.ip, right.host.ip)
    ));

    container.innerHTML = hostRows.map(({ host:h, latestCheck }) => {
      const rows = filteredResults().filter(r => r.ip === h.ip).map(enrich);
      const vulnCount = rows.filter(r => r.status === "취약").length;
      const goodCount = rows.filter(r => isGoodStatus(r.status)).length;
      const pending = rows.filter(r => r.status === "취약" && r.action_tag === "승인요청");
      const autoCount = vulnCount - pending.length;

      const body = pending.length
        ? `<table class="check-group-table">
            <thead><tr>
              <th style="width:26px"><input type="checkbox" class="group-select-all" data-group="ip:${h.ip}" title="이 IP 전체선택" /></th>
              <th>코드</th><th>취약점명</th><th>중요도</th><th>디테일</th>
            </tr></thead>
            <tbody>
              ${pending.map(r => `<tr>
                <td><input type="checkbox" class="check-item-select" data-key="${itemKey(h.ip, r.code)}" ${selectedCheckItems.has(itemKey(h.ip, r.code)) ? "checked" : ""} /></td>
                <td class="mono">${r.code}</td>
                <td>${r.title}</td>
                <td>${sevTag(r.severity)}</td>
                <td class="col-detail">${escapeHtml(r.detail)}</td>
              </tr>`).join("")}
            </tbody>
          </table>`
        : (rows.length === 0
            ? `<p class="check-group-empty">현재 필터(진단 영역)에 해당하는 점검 항목이 이 서버엔 없습니다.</p>`
            : `<p class="check-group-empty">승인 대기 중인 취약 항목이 없습니다.</p>`);

      return `<div class="check-group check-ip-group">
        <div class="check-group-head">
          <button type="button" class="check-group-toggle" aria-label="펼치기/접기">▸</button>
          <time class="check-group-time mono"${latestCheck ? ` datetime="${escapeHtml(latestCheck)}"` : ""}>${escapeHtml(formatLogTimestamp(latestCheck))}</time>
          <span class="mono link-cell check-group-navlink check-group-navlink-ip" data-nav-ip="${h.ip}" tabindex="0">${h.ip}</span>
          <span class="check-group-sub">${hostAndDomains(h)}</span>
          <span class="check-group-stats">
            <span class="check-group-result">
              <span class="check-result-item">${statusBadge("양호")}<b>${goodCount}</b></span>
              <span class="check-result-item">${statusBadge("취약")}<b>${vulnCount}</b></span>
              <span class="check-result-item">${actionTagBadge("자동조치")}<b>${autoCount}</b></span>
              <span class="check-result-item">${actionTagBadge("승인요청")}<b>${pending.length}</b></span>
            </span>
          </span>
        </div>
        <div class="check-group-body">${body}</div>
      </div>`;
    }).join("");

    wireCheckGroupInteractions(container, goToActionForIp);
  }

  function renderCheckByVulnGroups(){
    const container = document.getElementById("checkByVulnGroups");
    const allowedIps = new Set(filteredHosts().map(host => host.ip));
    const groups = filteredCodes().map(code => {
      const meta = itemMeta[code];
      const rows = rowsGoodFirst(results.filter(row => row.code === code && allowedIps.has(row.ip)).map(enrich));
      const vulnRows = rows.filter(row => row.status === "취약");
      const goodCount = rows.filter(row => row.status === "양호").length;

      let body;
      if(meta.action_tag !== "승인요청"){
        body = `<p class="check-group-empty">자동조치 대상 항목입니다 (승인 불필요).</p>`;
      }else if(vulnRows.length === 0){
        body = `<p class="check-group-empty">승인 대기 중인 취약 IP가 없습니다.</p>`;
      }else{
        body = `<table class="check-group-table">
          <thead><tr><th style="width:26px"><input type="checkbox" class="group-select-all" data-group="code:${escapeHtml(code)}" title="이 취약점 전체선택" /></th><th>IP</th><th>호스트명</th><th>디테일</th></tr></thead>
          <tbody>${vulnRows.map(row => `<tr>
            <td><input type="checkbox" class="check-item-select" data-key="${itemKey(row.ip, code)}" ${selectedCheckItems.has(itemKey(row.ip, code)) ? "checked" : ""} /></td>
            <td class="mono">${escapeHtml(row.ip)}</td>
            <td>${escapeHtml(hostMeta(row.ip).hostname)} · ${escapeHtml(OS_LABEL[hostMeta(row.ip).os_type] || hostMeta(row.ip).os_type || "")}</td>
            <td class="col-detail">${escapeHtml(row.detail)}</td>
          </tr>`).join("")}</tbody>
        </table>`;
      }

      const remediationLabel = meta.action_tag === "자동조치" ? "자동조치" : "승인조치";
      return `<div class="check-group check-vuln-group">
        <div class="check-group-head">
          <button type="button" class="check-group-toggle" aria-label="펼치기/접기">▸</button>
          <span class="mono link-cell check-group-navlink check-vuln-code" data-nav-code="${escapeHtml(code)}" tabindex="0">${escapeHtml(code)}</span>
          <span class="check-vuln-severity">${sevTag(meta.severity)}</span>
          <span class="check-group-sub">${escapeHtml(meta.title)}</span>
          <span class="check-group-stats check-vuln-status">
            <span class="check-group-result unified-status-summary">
              <span class="check-result-item">${statusBadge("양호")}<b>${goodCount}</b></span>
              <span class="check-result-item">${statusBadge("취약")}<b>${vulnRows.length}</b></span>
            </span>
          </span>
          <span class="check-vuln-action-type">${actionTagBadge(remediationLabel)}</span>
        </div>
        <div class="check-group-body">${body}</div>
      </div>`;
    }).join("");

    container.innerHTML = groups;
    wireCheckGroupInteractions(container, goToActionForCode);
  }

  function wireCheckGroupInteractions(container, navigateFn){
    container.querySelectorAll(".check-group-head").forEach(head => {
      const toggle = () => head.closest(".check-group").classList.toggle("expanded");
      head.addEventListener("click", e => {
        if(e.target.closest(".check-group-navlink")) return;
        toggle();
      });
    });
    container.querySelectorAll(".check-group-navlink").forEach(el => {
      const go = e => { e.stopPropagation(); navigateFn(el.dataset.navIp || el.dataset.navCode); };
      el.addEventListener("click", go);
      el.addEventListener("keydown", e => { if(e.key === "Enter") go(e); });
    });
    container.querySelectorAll(".check-item-select").forEach(cb => {
      cb.addEventListener("change", () => {
        if(cb.checked) selectedCheckItems.add(cb.dataset.key);
        else selectedCheckItems.delete(cb.dataset.key);
        syncGroupSelectAll(cb.closest(".check-group-table"));
        updateCheckApproveUI();
      });
    });
    container.querySelectorAll(".group-select-all").forEach(allCb => {
      allCb.addEventListener("click", e => e.stopPropagation());
      allCb.addEventListener("change", () => {
        const table = allCb.closest(".check-group-table");
        table.querySelectorAll(".check-item-select").forEach(cb => {
          cb.checked = allCb.checked;
          if(cb.checked) selectedCheckItems.add(cb.dataset.key);
          else selectedCheckItems.delete(cb.dataset.key);
        });
        updateCheckApproveUI();
      });
      syncGroupSelectAll(allCb.closest(".check-group-table"));
    });
  }

  function syncGroupSelectAll(tableEl){
    if(!tableEl) return;
    const allCb = tableEl.querySelector(".group-select-all");
    if(!allCb) return;
    const itemCbs = tableEl.querySelectorAll(".check-item-select");
    const total = itemCbs.length;
    const checkedCount = Array.from(itemCbs).filter(cb => cb.checked).length;
    allCb.checked = total > 0 && checkedCount === total;
    allCb.indeterminate = checkedCount > 0 && checkedCount < total;
  }

  function updateCheckApproveUI(){
    const n = selectedCheckItems.size;
    const total = allEligibleKeys().length;

    [["checkIpApproveBtn","checkIpApproveCount","selectAllCheckIps"],
     ["checkVulnApproveBtn","checkVulnApproveCount","selectAllCheckCodes"]].forEach(([btnId, countId, allId]) => {
      document.getElementById(btnId).disabled = n === 0;
      const countEl = document.getElementById(countId);
      if(countEl) countEl.textContent = n > 0 ? `${n}건 선택됨` : "";
      const allCb = document.getElementById(allId);
      allCb.checked = total > 0 && n === total;
      allCb.indeterminate = n > 0 && n < total;
    });
  }

  function compareIpAddresses(left, right){
    const a = left.split(".").map(Number);
    const b = right.split(".").map(Number);
    for(let i = 0; i < Math.max(a.length, b.length); i += 1){
      const diff = (a[i] || 0) - (b[i] || 0);
      if(diff !== 0) return diff;
    }
    return left.localeCompare(right, "ko", { numeric:true });
  }

  function renderActionByIp(){
    const body = document.getElementById("actionByIpBody");
    const table = body.closest("table");
    const listCard = table.closest(".action-list-card");
    const detailPane = document.getElementById("ipDetailPane");
    if(listCard) listCard.classList.remove("detail-open");
    if(detailPane){
      detailPane.classList.add("hidden");
      detailPane.innerHTML = "";
    }
    const direction = actionIpSort.direction === "asc" ? 1 : -1;
    const visibleHosts = filteredHosts();
    table.style.setProperty("--host-name-width", hostnameColumnWidth(visibleHosts));
    const rows = visibleHosts.map(host => ({
      host,
      latestCheck:latestCheckTimeForIp(host.ip),
      score:securityScoreForIp(host.ip).score
    }));

    rows.sort((left, right) => {
      if(actionIpSort.key === "score"){
        if(left.score === null && right.score !== null) return 1;
        if(left.score !== null && right.score === null) return -1;
      }
      let compared = 0;
      if(actionIpSort.key === "time") compared = logTimeNumber(left.latestCheck) - logTimeNumber(right.latestCheck);
      else if(actionIpSort.key === "score") compared = (left.score || 0) - (right.score || 0);
      else if(actionIpSort.key === "hostname") compared = left.host.hostname.localeCompare(right.host.hostname, "ko", { numeric:true });
      else compared = compareIpAddresses(left.host.ip, right.host.ip);
      return compared * direction;
    });

    body.innerHTML = rows.map(({ host, latestCheck, score }) => {
      const grade = securityGrade(score);
      return `<tr class="clickable" data-ip="${escapeHtml(host.ip)}" tabindex="0">
        <td class="mono action-ip-time">${escapeHtml(formatLogTimestamp(latestCheck))}</td>
        <td class="mono">${escapeHtml(host.ip)}</td>
        <td>${hostAndDomains(host)}</td>
        <td class="security-score-cell"><b>${score === null ? "평가 불가" : `${formatSecurityScore(score)}점`}</b><span class="score-ip-grade ${GRADE_CSS_CLASS[grade.label] || ""}">${grade.emoji} ${grade.label}</span></td>
      </tr>`;
    }).join("");

    table.querySelectorAll("th[data-sort-key]").forEach(th => {
      const key = th.dataset.sortKey;
      const active = key === actionIpSort.key;
      th.setAttribute("aria-sort", active ? (actionIpSort.direction === "asc" ? "ascending" : "descending") : "none");
      th.querySelector(".table-sort-btn").classList.toggle("active", active);
      th.querySelector(".sort-indicator").textContent = active ? (actionIpSort.direction === "asc" ? "▲" : "▼") : "";
      th.querySelector(".table-sort-btn").onclick = () => {
        if(actionIpSort.key === key) actionIpSort.direction = actionIpSort.direction === "asc" ? "desc" : "asc";
        else actionIpSort = { key, direction:key === "time" ? "desc" : "asc" };
        renderActionByIp();
      };
    });

    body.querySelectorAll("tr[data-ip]").forEach(tr => {
      const open = () => openIpDetail(tr.dataset.ip, tr);
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", e => { if(e.key === "Enter") open(); });
    });
  }

  function openIpDetail(ip, trEl){
    const pane = document.getElementById("ipDetailPane");
    const listCard = trEl.closest(".action-list-card");
    if(trEl.classList.contains("row-active") && !pane.classList.contains("hidden")){
      trEl.classList.remove("row-active");
      pane.classList.add("hidden");
      pane.innerHTML = "";
      if(listCard) listCard.classList.remove("detail-open");
      return;
    }

    document.querySelectorAll("#actionByIpBody tr").forEach(tr => tr.classList.remove("row-active"));
    trEl.classList.add("row-active");
    if(listCard) listCard.classList.add("detail-open");

    const host = hostMeta(ip);
    const rows = rowsGoodFirst(filteredResults().filter(r => r.ip === ip).map(enrich));
    const vulnRows = rows.filter(r => r.status === "취약");
    const good = rows.length - vulnRows.length;
    const resultTotal = Math.max(rows.length, 1);

    pane.classList.remove("hidden");
    pane.innerHTML = `
      <div class="detail-top">
        <div>
          <p class="detail-title mono">${ip}</p>
          <p class="detail-sub">${host.hostname} · ${OS_LABEL[host.os_type] || host.os_type} · 진단영역 ${(host.domains || ["UNIX"]).join("/")}</p>
        </div>
        <div class="stat-group">
          <div class="stat good"><div class="n">${good}</div><div class="l">양호</div></div>
          <div class="stat vuln"><div class="n">${vulnRows.length}</div><div class="l">취약</div></div>
          <button class="btn btn-ghost detail-stat-report" data-report="${ip}">리포트 생성 (PDF/CSV)</button>
        </div>
      </div>

      <div class="result-gauge" role="img" aria-label="양호 ${good}건, 취약 ${vulnRows.length}건">
        <span class="gauge-good" style="width:${good/resultTotal*100}%"></span>
        <span class="gauge-vuln" style="width:${vulnRows.length/resultTotal*100}%"></span>
      </div>
      <div class="result-gauge-legend">
        <span><span class="gauge-dot good"></span>양호 ${good}건</span>
        <span><span class="gauge-dot vuln"></span>취약 ${vulnRows.length}건</span>
      </div>

      <div class="table-wrap" style="margin-top:20px">
        <table>
          <thead><tr><th>코드</th><th>상태</th><th>디테일</th><th>액션태그</th><th>임팩트</th></tr></thead>
          <tbody>
            ${rows.map(r => `<tr>
              <td class="mono">${r.code} <span class="hint" style="display:inline">${itemMeta[r.code].domain}</span></td>
              <td>${statusBadge(r.status)}</td>
              <td class="col-detail">${escapeHtml(r.detail)}</td>
              <td>${actionTagBadge(r.action_tag)}</td>
              <td class="col-impact">${escapeHtml(r.impact)}</td>
            </tr>`).join("")}
          </tbody>
        </table>
      </div>

    `;
    requestAnimationFrame(() => pane.scrollIntoView({ behavior:"smooth", block:"start" }));
    pane.querySelector("[data-report]").addEventListener("click", () => {
      logReport("개별 IP", `${ip} (${host.hostname})`, ip, "전체 출력", false, [ip], "all");
      alert(`${ip} (${host.hostname}) 리포트를 생성했습니다. "리포트 기록" 탭에서 열어 PDF/CSV로 저장할 수 있습니다.`);
    });
  }

  function renderActionByVuln(){
    const body = document.getElementById("actionByVulnBody");
    const table = body.closest("table");
    const listCard = table.closest(".action-list-card");
    const detailPane = document.getElementById("vulnDetailPane");
    if(listCard) listCard.classList.remove("detail-open");
    if(detailPane){
      detailPane.classList.add("hidden");
      detailPane.innerHTML = "";
    }

    const allowedIps = new Set(filteredHosts().map(host => host.ip));
    const records = filteredCodes().map(code => {
      const meta = itemMeta[code];
      const rows = results.filter(row => row.code === code && allowedIps.has(row.ip));
      return {
        code, meta,
        good:rows.filter(row => row.status === "양호").length,
        vuln:rows.filter(row => row.status === "취약").length
      };
    });
    const direction = actionVulnSort.direction === "asc" ? 1 : -1;
    records.sort((left, right) => {
      let compared = 0;
      if(actionVulnSort.key === "title") compared = left.meta.title.localeCompare(right.meta.title, "ko", { numeric:true });
      else if(actionVulnSort.key === "severity") compared = (SECURITY_SEV_WEIGHT[left.meta.severity] || 0) - (SECURITY_SEV_WEIGHT[right.meta.severity] || 0);
      else if(actionVulnSort.key === "vuln") compared = left.vuln - right.vuln;
      else compared = left.code.localeCompare(right.code, "ko", { numeric:true });
      return compared * direction;
    });

    body.innerHTML = records.map(({ code, meta, good, vuln }) => `<tr class="clickable" data-code="${escapeHtml(code)}" tabindex="0">
      <td class="mono">${escapeHtml(code)}</td>
      <td class="severity-cell">${sevTag(meta.severity)}</td>
      <td>${escapeHtml(meta.title)}</td>
      <td class="vuln-status-cell"><span class="check-group-result unified-status-summary"><span class="check-result-item">${statusBadge("양호")}<b>${good}</b></span><span class="check-result-item">${statusBadge("취약")}<b>${vuln}</b></span></span></td>
    </tr>`).join("");

    table.querySelectorAll("th[data-vuln-sort-key]").forEach(th => {
      const key = th.dataset.vulnSortKey;
      const active = key === actionVulnSort.key;
      th.setAttribute("aria-sort", active ? (actionVulnSort.direction === "asc" ? "ascending" : "descending") : "none");
      th.querySelector(".table-sort-btn").classList.toggle("active", active);
      th.querySelector(".sort-indicator").textContent = active ? (actionVulnSort.direction === "asc" ? "▲" : "▼") : "";
      th.querySelector(".table-sort-btn").onclick = () => {
        if(actionVulnSort.key === key) actionVulnSort.direction = actionVulnSort.direction === "asc" ? "desc" : "asc";
        else actionVulnSort = { key, direction:"asc" };
        renderActionByVuln();
      };
    });
    body.querySelectorAll("tr[data-code]").forEach(tr => {
      const open = () => openVulnDetail(tr.dataset.code, tr);
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", event => { if(event.key === "Enter") open(); });
    });
  }

  function openVulnDetail(code, trEl){
    const pane = document.getElementById("vulnDetailPane");
    const listCard = trEl.closest(".action-list-card");
    if(trEl.classList.contains("row-active") && !pane.classList.contains("hidden")){
      trEl.classList.remove("row-active");
      pane.classList.add("hidden");
      pane.innerHTML = "";
      if(listCard) listCard.classList.remove("detail-open");
      return;
    }

    document.querySelectorAll("#actionByVulnBody tr[data-code]").forEach(tr => tr.classList.remove("row-active"));
    trEl.classList.add("row-active");
    if(listCard) listCard.classList.add("detail-open");
    const meta = itemMeta[code];
    const allowedIps = new Set(filteredHosts().map(host => host.ip));
    const rows = rowsGoodFirst(results.filter(row => row.code === code && allowedIps.has(row.ip)).map(enrich));
    const good = rows.filter(row => row.status === "양호").length;
    const autoCount = rows.filter(row => row.status === "취약" && meta.action_tag === "자동조치").length;
    const approveCount = rows.filter(row => row.status === "취약" && meta.action_tag === "승인요청").length;

    pane.classList.remove("hidden");
    pane.innerHTML = `<div class="detail-top">
      <div><p class="detail-title">${escapeHtml(meta.title)}</p><p class="detail-sub mono">${escapeHtml(code)} · ${escapeHtml(meta.domain)} · 중요도 ${escapeHtml(meta.severity)}</p></div>
      <div class="stat-group">
        <div class="stat good"><div class="n">${good}</div><div class="l">양호</div></div>
        <div class="stat"><div class="n">${autoCount}</div><div class="l">자동조치</div></div>
        <div class="stat vuln"><div class="n">${approveCount}</div><div class="l">승인요청</div></div>
        <button class="btn btn-ghost detail-stat-report" data-code-report="${escapeHtml(code)}">리포트 생성 (PDF/CSV)</button>
      </div>
    </div>
    <div class="table-wrap" style="margin-top:4px"><table>
      <thead><tr><th>IP</th><th>호스트명</th><th>상태</th><th>디테일</th><th>액션태그</th></tr></thead>
      <tbody>${rows.map(row => `<tr><td class="mono">${escapeHtml(row.ip)}</td><td>${escapeHtml(hostMeta(row.ip).hostname || "-")}</td><td>${statusBadge(row.status)}</td><td class="col-detail">${escapeHtml(row.detail)}</td><td>${row.status === "취약" ? actionTagBadge(row.action_tag) : "-"}</td></tr>`).join("")}</tbody>
    </table></div>
    ${manualFix[code] ? `<div class="manual-fix"><div class="manual-fix-head"><span class="modal-section-label" style="margin:0">수동 조치 명령어 안내</span><button type="button" class="btn btn-ghost" id="manualFixCopyBtn" style="padding:5px 10px; font-size:12px">복사</button></div><pre class="manual-fix-code"><code>${escapeHtml(manualFix[code])}</code></pre><p class="hint" style="margin:8px 0 0">실제 서버의 계정명·경로·정책 값에 맞게 수정한 뒤 실행하세요. 대상 서버에 직접 접속해 root 권한으로 실행해야 합니다.</p></div>` : ""}`;

    pane.querySelector("[data-code-report]").addEventListener("click", () => {
      logReport("개별 취약점", `${code} (${meta.title})`, code, "전체 IP 출력", true, [code], "all");
      alert(`${code} 리포트를 생성했습니다. 리포트 기록 탭에서 PDF/CSV로 저장할 수 있습니다.`);
    });
    const copyBtn = pane.querySelector("#manualFixCopyBtn");
    if(copyBtn) copyBtn.addEventListener("click", async () => {
      try{
        await navigator.clipboard.writeText(manualFix[code]);
        copyBtn.textContent = "복사됨";
        setTimeout(() => { copyBtn.textContent = "복사"; }, 1500);
      }catch(err){
        alert("클립보드 복사에 실패했습니다. 명령어를 직접 선택해 복사해 주세요.");
      }
    });
    requestAnimationFrame(() => pane.scrollIntoView({ behavior:"smooth", block:"start" }));
  }

  function logTimeValue(row){
    return row.saved_at || row.timestamp || "";
  }

  function logTimeNumber(value){
    if(value instanceof Date) return Number.isNaN(value.getTime()) ? 0 : value.getTime();
    if(typeof value === "number") return Number.isFinite(value) ? value : 0;

    const number = Date.parse(value);
    if(!Number.isNaN(number)) return number;

    const match = String(value || "").match(
      /^(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})\.?\s*(?:(오전|오후)\s*)?(\d{1,2}):(\d{2})(?::(\d{2}))?$/
    );
    if(!match) return 0;
    let hour = Number(match[5]);
    if(match[4] === "오전" && hour === 12) hour = 0;
    if(match[4] === "오후" && hour < 12) hour += 12;
    return Date.UTC(
      Number(match[1]), Number(match[2]) - 1, Number(match[3]),
      hour - 9, Number(match[6]), Number(match[7] || 0)
    );
  }

  function formatTimestamp(value, includeSeconds=false){
    if(!value) return "-";
    const number = logTimeNumber(value);
    if(!number) return String(value);
    const parts = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {
      timeZone:"Asia/Seoul", year:"numeric", month:"2-digit", day:"2-digit",
      hour:"2-digit", minute:"2-digit", second:includeSeconds ? "2-digit" : undefined,
      hourCycle:"h23"
    }).formatToParts(new Date(number)).map(part => [part.type, part.value]));
    const dateAndMinute = `${parts.year}.${parts.month}.${parts.day} ${parts.hour}:${parts.minute}`;
    return includeSeconds ? `${dateAndMinute}:${parts.second}` : dateAndMinute;
  }

  function formatLogTimestamp(value){
    return formatTimestamp(value, false);
  }

  function formatReportTimestamp(value){
    return formatTimestamp(value, true);
  }

  function latestCheckTimeForIp(ip){
    const runTimes = checkRuns
      .filter(run => run.ip === ip)
      .map(run => run.created_at)
      .filter(Boolean);
    const resultTimes = results
      .filter(row => row.ip === ip)
      .map(logTimeValue)
      .filter(Boolean);
    return [...runTimes, ...resultTimes].reduce((latest, value) => (
      logTimeNumber(value) > logTimeNumber(latest) ? value : latest
    ), "");
  }

  function renderDbResults(){
    const body = document.getElementById("dbResultsBody");
    const summary = document.getElementById("checkLogSummary");
    if(!body) return;
    if(dbResultsError){
      if(summary) summary.textContent = "불러오기 실패";
      body.innerHTML = `<tr class="empty-row"><td colspan="4">점검 로그를 불러오지 못했습니다: ${escapeHtml(dbResultsError)}<br />백엔드(<span class="mono">uvicorn backend.main:app --port 8000</span>)가 실행 중인지 확인해 주세요.</td></tr>`;
      return;
    }
    if(checkRuns.length === 0){
      if(summary) summary.textContent = "표시할 로그 없음";
      body.innerHTML = `<tr class="empty-row"><td colspan="4">저장된 점검 로그가 없습니다. IP 점검을 실행하면 호스트별 최신 로그가 표시됩니다.</td></tr>`;
      return;
    }

    const logs = checkRuns.map(run => ({
      host:run.host || "-", ip:run.ip || "-", domains:[run.domain],
      latestCheck:run.created_at, good:run.good_count, vuln:run.vuln_count,
      autoCount:run.auto_count || 0, approveCount:run.approve_count || 0,
      total:run.total_count
    }));

    if(summary){
      const latest = logs[0] ? formatLogTimestamp(logs[0].latestCheck) : "-";
      summary.textContent = `실행 이력 ${logs.length}건 · 최근 ${latest}`;
    }

    body.innerHTML = logs.map(log => `<tr>
        <td class="mono log-time-cell">${escapeHtml(formatLogTimestamp(log.latestCheck))}</td>
        <td class="log-host-cell"><strong>${escapeHtml(log.host)}</strong></td>
        <td class="log-ip-cell"><span class="mono">${escapeHtml(log.ip)}</span><span class="log-ip-domains">${domainBoxes(log.domains)}</span></td>
        <td><div class="log-result-summary"><span class="check-result-item">${statusBadge("양호")}<b>${log.good}</b></span><span class="check-result-item">${statusBadge("취약")}<b>${log.vuln}</b></span><span class="check-result-item">${actionTagBadge("자동조치")}<b>${log.autoCount}</b></span><span class="check-result-item">${actionTagBadge("승인요청")}<b>${log.approveCount}</b></span></div></td>
      </tr>`).join("");
  }

  function initDbResults(){
    const btn = document.getElementById("dbResultsRefreshBtn");
    if(btn) btn.addEventListener("click", loadDbResults);
  }

  function initLogin(){
    async function doLogin(){
      const id = document.getElementById("loginId").value.trim();
      const password = document.getElementById("loginPw").value;
      if(!id || !password){
        alert("아이디와 비밀번호를 입력해 주세요.");
        return;
      }
      let response;
      try{
        response = await API.login(id, password);
      }catch(error){
        alert(error.message || "로그인에 실패했습니다.");
        return;
      }
      currentUserProfile = response.user;
      currentUser = response.user.username;
      currentLoginId = response.user.login_id;
      document.getElementById("accountName").textContent = currentUser;
      document.getElementById("topNav").classList.remove("hidden");
      await loadInitialData();
      renderAll();
      loadDbResults();
      showView("overview");
    }
    document.getElementById("loginBtn").addEventListener("click", doLogin);
    ["loginId","loginPw"].forEach(id => {
      document.getElementById(id).addEventListener("keydown", e => {
        if(e.key === "Enter") doLogin();
      });
    });
  }

  function initLogout(){
    document.getElementById("logoutBtn").addEventListener("click", async () => {
      await API.logout();
      closeAccountMenu();
      closeAccountVerifyModal();
      currentUser = null;
      currentLoginId = null;
      currentUserProfile = null;
      document.getElementById("topNav").classList.add("hidden");
      document.getElementById("navStats").innerHTML = "";
      document.getElementById("loginId").value = "";
      document.getElementById("loginPw").value = "";
      showView("login");
    });
  }

  function initNav(){
    document.querySelectorAll(".nav-tab").forEach(btn => {
      btn.addEventListener("click", () => showView(btn.dataset.view));
    });
    document.querySelectorAll("[data-goto]").forEach(btn => {
      btn.addEventListener("click", () => showView(btn.dataset.goto));
    });
  }

  const DOMAIN_RUN_LABEL = { ALL:"전체", UNIX:"UNIX", WEB:"WEB", DBMS:"DBMS" };
  let domainRunMode = "check-auto";

  function selectedRunDomains(){
    return Array.from(document.querySelectorAll(`input[name="domainRunTarget"]:checked`)).map(input => input.value);
  }

  function eligibleSelectedIps(domains){
    const selectedDomains = domains.includes("ALL") ? ["ALL"] : domains;
    return registeredIps
      .filter(host => selectedIps.has(host.ip))
      .filter(host => selectedDomains.includes("ALL") || (host.domains || ["UNIX"]).some(domain => selectedDomains.includes(domain)))
      .map(host => host.ip);
  }

  function runDomainLabel(domains){
    return domains.includes("ALL") ? "모든 IP의 모든 영역" : domains.map(domain => DOMAIN_RUN_LABEL[domain]).join(" + ");
  }

  function closeDomainRunModal(){
    document.getElementById("domainRunModalOverlay").classList.add("hidden");
  }

  function updateDomainRunSelection(changedInput){
    const allInput = document.querySelector(`input[name="domainRunTarget"][value="ALL"]`);
    const areaInputs = Array.from(document.querySelectorAll(`input[name="domainRunTarget"]:not([value="ALL"])`));
    if(changedInput && changedInput.value === "ALL" && changedInput.checked){
      areaInputs.forEach(input => { input.checked = false; });
    }else if(changedInput && changedInput.value !== "ALL" && changedInput.checked){
      allInput.checked = false;
    }
    if(!allInput.checked && !areaInputs.some(input => input.checked)) allInput.checked = true;

    const domains = selectedRunDomains();
    const targetCount = eligibleSelectedIps(domains).length;
    document.getElementById("domainRunTargetSummary").textContent = `${runDomainLabel(domains)} · 실행 대상 IP ${targetCount}대`;
    document.getElementById("domainRunConfirmBtn").disabled = targetCount === 0;
  }

  function openDomainRunModal(mode="check-auto"){
    if(selectedIps.size === 0) return;
    domainRunMode=mode;
    const checkOnly=mode === "check-only";
    document.getElementById("domainRunModalTitle").textContent=checkOnly ? "진단영역별 점검만" : "진단영역별 점검 + 자동조치";
    document.getElementById("domainRunConfirmBtn").textContent=checkOnly ? "점검만 실행" : "점검 + 자동조치 실행";
    const options = document.getElementById("domainRunOptions");
    const domains = ["ALL", "UNIX", "WEB", "DBMS"];
    options.innerHTML = domains.map((domain, index) => {
      const count = eligibleSelectedIps([domain]).length;
      const description = domain === "ALL" ? "모든 IP의 모든 진단영역" : `${domain} 영역 등록 IP`;
      return `<label class="domain-run-option ${count === 0 ? "disabled" : ""}">
        <input type="checkbox" name="domainRunTarget" value="${domain}" ${index === 0 ? "checked" : ""} ${count === 0 ? "disabled" : ""} />
        <span><b>${DOMAIN_RUN_LABEL[domain]}</b><small>${description}</small></span>
        <strong>${count}대</strong>
      </label>`;
    }).join("");
    options.querySelectorAll(`input[name="domainRunTarget"]`).forEach(input => {
      input.addEventListener("change", () => updateDomainRunSelection(input));
    });
    updateDomainRunSelection();
    document.getElementById("domainRunModalOverlay").classList.remove("hidden");
  }

  async function runSelectedDomainCheck(){
    const domains = selectedRunDomains();
    if(domains.length === 0) return;
    const ips = eligibleSelectedIps(domains);
    const domainLabel = runDomainLabel(domains);
    const checkOnly = domainRunMode === "check-only";
    const actionLabel = checkOnly ? "점검만" : "점검 + 자동조치";
    if(ips.length === 0){
      alert("선택한 진단영역에 등록된 IP가 없습니다.");
      return;
    }
    if(!await showAppConfirm(`${domainLabel}에 대해 ${actionLabel} 실행합니다.\n대상 IP ${ips.length}대: ${ips.join(", ")}\n\n계속할까요?`)) return;

    closeDomainRunModal();
    const btn = document.getElementById(checkOnly ? "domainRunCheckBtn" : "bulkCheckRemediateBtn");
    const progressLabel = document.getElementById("selectedCount");
    const original = btn.textContent;
    btn.disabled = true;
    try{
      remediationUpdates=[];remediationScoreChange=null;
      const { job_id } = checkOnly ? await API.startCheckOnlyJob(ips, domains) : await API.startCheckJob(ips, domains);
      const job = await pollJob(job_id, current => {
        const elapsed = Math.round((Date.now()/1000) - current.created_at);
        btn.textContent = `실행 중... (${elapsed}초)`;
        if(checkOnly && progressLabel)progressLabel.textContent = `실행 중... (${elapsed}초)`;
      });
      await reloadHostsAndResults();
      if(!checkOnly && job.result){
        remediationUpdates=job.result.remediation_updates || [];
        remediationUpdateTime=formatLogTimestamp(new Date((job.finished_at || Date.now()/1000)*1000).toISOString());
        remediationScoreChange={initial:job.result.initial_score,final:job.result.final_score};
      }
      renderAll();
      renderDbResults();
      if(job.status === "success"){
        if(checkOnly){
          const summary=ips.map(ip=>{
            const rows=results.filter(row=>row.ip===ip);
            const good=rows.filter(row=>row.status==="양호" || row.status==="O" || row.status==="o").length;
            const vuln=rows.length-good;
            const pending=rows.filter(row=>row.status==="취약" && (itemMeta[row.code]||{}).action_tag==="승인요청").length;
            const score=securityScoreForIp(ip).score;
            return {ip,good,vuln,auto:Math.max(0,vuln-pending),pending,score};
          });
          openCheckSummaryModal(summary);
        }else{
          alert(`${domainLabel}의 IP ${ips.length}대에 대해 ${actionLabel} 완료했습니다.`);
          showView("check");
        }
      }else{
        showJobFailure(`${actionLabel} 실행 중 오류가 발생했습니다.\n${job.error || ""}\n\n--- 실행 로그(마지막 부분) ---\n${job.log.slice(-1500)}`,job);
      }
    }catch(err){
      alert(actionLabel + " 요청 실패: " + err.message);
    }finally{
      btn.textContent = original;
      updateBulkActionUI();
    }
  }

  function initDomainRunModal(){
    document.getElementById("domainRunCloseBtn").addEventListener("click", closeDomainRunModal);
    document.getElementById("domainRunCheckBtn").addEventListener("click",()=>{domainRunMode="check-only";runSelectedDomainCheck();});
    document.getElementById("domainRunConfirmBtn").addEventListener("click", runSelectedDomainCheck);
    document.getElementById("domainRunModalOverlay").addEventListener("click", event => {
      if(event.target.id === "domainRunModalOverlay") closeDomainRunModal();
    });
    document.getElementById("checkSummaryCloseBtn").addEventListener("click",()=>document.getElementById("checkSummaryModalOverlay").classList.add("hidden"));
  }

  function openCheckSummaryModal(rows){
    const overlay=document.getElementById("checkSummaryModalOverlay");
    const list=document.getElementById("checkSummaryList");
    list.innerHTML=rows.map(item=>`<div class="check-summary-row"><div class="check-summary-ip mono">${escapeHtml(item.ip)}</div><div class="check-summary-stats"><span class="check-result-item">${statusBadge("양호")}<b>${item.good}</b></span><span class="check-result-item">${statusBadge("취약")}<b>${item.vuln}</b></span><span class="check-result-item">${actionTagBadge("자동조치")}<b>${item.auto}</b></span><span class="check-result-item">${actionTagBadge("승인요청")}<b>${item.pending}</b></span></div><div class="check-summary-score">${item.score===null?"-":formatSecurityScore(item.score)+"점"}</div></div>`).join("");
    overlay.classList.remove("hidden");
  }

  function initIpRegistration(){
    document.getElementById("addSingleIpBtn").addEventListener("click", async () => {
      const input = document.getElementById("singleIpInput");
      const hostInput = document.getElementById("singleHostnameInput");
      const val = input.value.trim();
      const hostname = hostInput.value.trim() || "미확인";
      if(!isIpLike(val)){
        alert("올바른 IP 형식이 아닙니다. 예: 192.168.0.132");
        return;
      }

      const domains = ["UNIX"];
      if(document.getElementById("singleDomainWeb").checked) domains.push("WEB");
      if(document.getElementById("singleDomainDbms").checked) domains.push("DBMS");

      const btn = document.getElementById("addSingleIpBtn");
      btn.disabled = true;
      try{
        const result = await API.addHost({ ip:val, hostname, domains });
        if(!result.ok){
          alert("이미 등록된 IP입니다.");
          return;
        }
        await reloadHostsAndResults();
        input.value = "";
        hostInput.value = "";
        document.getElementById("singleDomainWeb").checked = false;
        document.getElementById("singleDomainDbms").checked = false;
        renderAll();
      }catch(err){
        alert("등록 요청 실패: " + err.message);
      }finally{
        btn.disabled = false;
      }
    });

    document.getElementById("singleHostnameInput").addEventListener("keydown", e => {
      if(e.key === "Enter") document.getElementById("addSingleIpBtn").click();
    });

    document.getElementById("singleIpInput").addEventListener("keydown", e => {
      if(e.key === "Enter") document.getElementById("addSingleIpBtn").click();
    });

    document.getElementById("bulkIpFile").addEventListener("change", e => {
      const file = e.target.files[0];
      if(!file) return;
      const reader = new FileReader();
      reader.onload = async () => {
        const lines = String(reader.result).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        let added = 0, skipped = 0;
        for(const line of lines){
          const cleaned = line.replace(/^[-*]\s*/, "");
          const [ipPart, hostPart, ...domainParts] = cleaned.split(",").map(p => (p || "").trim());

          if(!isIpLike(ipPart)){
            skipped++;
            continue;
          }

          const requestedDomains = domainParts
            .flatMap(part => part.split("|"))
            .map(domain => domain.toUpperCase())
            .filter(domain => ["UNIX", "WEB", "DBMS"].includes(domain));
          const domains = Array.from(new Set(requestedDomains.length ? requestedDomains : ["UNIX"]));
          if(!domains.includes("UNIX")) domains.unshift("UNIX");

          try{
            const result = await API.addHost({ ip:ipPart, hostname:hostPart || "미확인", domains });
            if(result.ok) added++;
            else skipped++;
          }catch(err){
            skipped++;
          }
        }
        await reloadHostsAndResults();
        renderAll();
        alert(`총 ${added}개의 IP를 일괄 등록했습니다.` + (skipped ? ` (형식 오류/중복/실패 ${skipped}건 제외)` : ""));
        e.target.value = "";
      };
      reader.readAsText(file);
    });

    document.getElementById("selectAllIps").addEventListener("change", e => {
      if(e.target.checked) registeredIps.forEach(r => selectedIps.add(r.ip));
      else selectedIps.clear();
      renderIpTable();
    });

    document.getElementById("bulkCheckRemediateBtn").addEventListener("click",()=>openDomainRunModal("check-auto"));
  }

  function toggleAllEligible(checked){
    if(checked) allEligibleKeys().forEach(k => selectedCheckItems.add(k));
    else selectedCheckItems.clear();
    renderCheckView();
  }

  async function approveSelectedCheckItems(){
    if(selectedCheckItems.size === 0) return;
    const keys = Array.from(selectedCheckItems);
    const items = keys.map(k => {
      const [ip, code] = k.split("|");
      return { ip, code };
    });
    const list = items.map(it => `${it.ip} / ${it.code}`);
    const beforeByKey = new Map(items.map(item => {
      const row = results.find(r => r.ip === item.ip && r.code === item.code);
      return [itemKey(item.ip, item.code), {
        status:row ? row.status : "결과 없음",
        title:(itemMeta[item.code] || {}).title || "-"
      }];
    }));
    if(!await showAppConfirm(`선택한 항목 ${list.length}건을 승인조치하고 재점검합니다.\n${list.join("\n")}\n\nAnsible 플레이북(remediate_approved.yml → check.yml)이 실제 대상 서버에 접속해 조치를 실행합니다. 계속할까요?`)) return;

    const btns = [document.getElementById("checkIpApproveBtn"), document.getElementById("checkVulnApproveBtn")];
    const originals = btns.map(b => b.textContent);
    btns.forEach(b => { b.disabled = true; });
    try{
      const { job_id } = await API.startRemediateJob(items);
      const job = await pollJob(job_id, j => {
        const elapsed = Math.round((Date.now()/1000) - j.created_at);
        btns.forEach(b => { b.textContent = `실행 중... (${elapsed}초)`; });
      });
      await reloadHostsAndResults();
      recordRemediationUpdates(items, beforeByKey, job, null);
      if(job.status === "success"){
        alert(`선택한 항목 ${list.length}건을 승인조치하고 재점검했습니다.\n${list.join("\n")}`);
      } else {
        showJobFailure(`승인조치 실행 중 오류가 발생했습니다.\n${job.error || ""}\n\n--- 실행 로그(마지막 부분) ---\n${job.log.slice(-1500)}`,job);
      }
    }catch(err){
      recordRemediationUpdates(items, beforeByKey, null, err.message || String(err));
      alert("승인조치 요청 실패: " + err.message);
    }finally{
      btns.forEach((b, i) => { b.textContent = originals[i]; });
      selectedCheckItems.clear();
      renderCheckView();
      renderSecurityScore();
      renderActionByIp();
      renderActionByVuln();
    }
  }

  function initCheckApprovals(){
    document.getElementById("selectAllCheckIps").addEventListener("change", e => toggleAllEligible(e.target.checked));
    document.getElementById("selectAllCheckCodes").addEventListener("change", e => toggleAllEligible(e.target.checked));
    document.getElementById("checkIpApproveBtn").addEventListener("click", approveSelectedCheckItems);
    document.getElementById("checkVulnApproveBtn").addEventListener("click", approveSelectedCheckItems);
  }

  function initActionReports(){
    document.querySelectorAll(".latest-evidence-btn").forEach(button => button.addEventListener("click",()=>{
      if(latestEvidenceJob) window.location.href=API.evidenceUrl(latestEvidenceJob.id);
    }));
    document.getElementById("ipReportAllBtn").addEventListener("click", () => {
      openReportModal("ip", [], "IP 전체");
    });
    document.getElementById("vulnReportAllBtn").addEventListener("click", () => {
      openReportModal("code", [], "취약점 전체");
    });
  }

  let reportModalKind = "ip";
  let reportModalContextLabel = "";

  function openReportModal(kind, preselectValues, contextLabel){
    reportModalKind = kind;
    reportModalContextLabel = contextLabel;
    document.getElementById("reportModalTitle").textContent = `리포트 생성 — ${contextLabel}`;

    const listEl = document.getElementById("reportSelectList");
    if(kind === "code"){
      document.getElementById("reportSelectLabel").textContent = "취약점 선택";
      document.getElementById("reportScopeAllLabel").textContent = "전체 IP 출력";
      document.getElementById("reportScopeVulnLabel").textContent = "취약 IP 출력";
      listEl.innerHTML = Object.keys(itemMeta).map(code => `
        <label>
          <input type="checkbox" class="report-select-cb" value="${code}" ${preselectValues.includes(code) ? "checked" : ""} />
          <span class="mono">${code}</span> ${itemMeta[code].title}
        </label>`).join("");
    } else {
      document.getElementById("reportSelectLabel").textContent = "IP 선택";
      document.getElementById("reportScopeAllLabel").textContent = "양호, 취약 항목";
      document.getElementById("reportScopeVulnLabel").textContent = "취약 항목만";
      const ipHosts = [...hosts].sort((left, right) => (
        logTimeNumber(latestCheckTimeForIp(right.ip)) - logTimeNumber(latestCheckTimeForIp(left.ip))
        || compareIpAddresses(left.ip, right.ip)
      ));
      listEl.innerHTML = ipHosts.map(h => `
        <label>
          <input type="checkbox" class="report-select-cb" value="${h.ip}" ${preselectValues.includes(h.ip) ? "checked" : ""} />
          <span class="mono">${h.ip}</span> ${escapeHtml(h.hostname)}
        </label>`).join("");
    }

    document.getElementById("reportSelectAll").checked = false;
    document.getElementById("reportSelectAll").indeterminate = false;
    document.querySelector('input[name="reportScope"][value="all"]').checked = true;
    document.getElementById("reportModalOverlay").classList.remove("hidden");
  }

  function closeReportModal(){
    document.getElementById("reportModalOverlay").classList.add("hidden");
  }

  function initReportModal(){
    document.getElementById("reportModalCancel").addEventListener("click", closeReportModal);
    document.getElementById("reportModalOverlay").addEventListener("click", e => {
      if(e.target.id === "reportModalOverlay") closeReportModal();
    });
    document.getElementById("reportSelectAll").addEventListener("change", e => {
      document.querySelectorAll(".report-select-cb").forEach(cb => { cb.checked = e.target.checked; });
    });
    document.getElementById("reportSelectList").addEventListener("change", e => {
      if(!e.target.classList.contains("report-select-cb")) return;
      const cbs = document.querySelectorAll(".report-select-cb");
      const total = cbs.length;
      const checkedCount = Array.from(cbs).filter(cb => cb.checked).length;
      const allCb = document.getElementById("reportSelectAll");
      allCb.checked = total > 0 && checkedCount === total;
      allCb.indeterminate = checkedCount > 0 && checkedCount < total;
    });
    document.getElementById("reportModalConfirm").addEventListener("click", () => {
      const selected = Array.from(document.querySelectorAll(".report-select-cb:checked")).map(cb => cb.value);
      const isCode = reportModalKind === "code";
      if(selected.length === 0){
        alert(`리포트에 포함할 ${isCode ? "취약점" : "IP"}을 1개 이상 선택해 주세요.`);
        return;
      }
      const scope = document.querySelector('input[name="reportScope"]:checked').value;
      const scopeLabel = isCode
        ? (scope === "all" ? "전체 IP 출력" : "취약 IP 출력")
        : (scope === "all" ? "양호, 취약 항목" : "취약 항목만");
      const targetLabel = isCode ? "대상 취약점" : "대상 IP";
      logReport(isCode ? "취약점 선택" : "IP 선택", reportModalContextLabel, selected.join(", "), scopeLabel, isCode, selected, scope);
      alert(`${reportModalContextLabel} 리포트를 생성했습니다.\n${targetLabel}: ${selected.join(", ")}\n출력 범위: ${scopeLabel}\n\n"리포트 기록" 탭에서 열어 PDF/CSV로 저장할 수 있습니다.`);
      closeReportModal();
    });
  }

  async function logReport(kind, context, targets, scope, isCode, targetList, scopeRaw){
    const entry = {
      timestamp: new Date().toISOString(),
      user: currentUser || "admin",
      kind, context, targets, scope,
      isCode: !!isCode, targetList: targetList || [], scopeRaw: scopeRaw || "all"
    };
    reportLog = await API.addReportLog(entry);
    renderReportLog();
  }

  function sortReportRows(rows){
    const domainOrder = { UNIX:0, DBMS:1, WEB:2, WINDOWS:3 };
    const codeNumber = code => Number((String(code || "").match(/(\d+)$/) || [])[1]) || 0;
    return [...rows].sort((left, right) => {
      const leftDomain = domainOfCode(String(left.code || ""));
      const rightDomain = domainOfCode(String(right.code || ""));
      return compareIpAddresses(left.ip || "", right.ip || "")
        || (domainOrder[leftDomain] ?? 99) - (domainOrder[rightDomain] ?? 99)
        || codeNumber(left.code) - codeNumber(right.code)
        || String(left.code || "").localeCompare(String(right.code || ""), "ko", { numeric:true });
    });
  }

  function reportRows(entry){
    let rows = entry.isCode
      ? results.filter(r => entry.targetList.includes(r.code))
      : results.filter(r => entry.targetList.includes(r.ip));
    if(entry.scopeRaw === "vuln") rows = rows.filter(r => r.status === "취약");
    return sortReportRows(rows.map(enrich));
  }

  function reportTargetIps(entry){
    const ips = entry.isCode
      ? reportRows(entry).map(row => row.ip)
      : ((Array.isArray(entry.targetList) && entry.targetList.length)
          ? entry.targetList
          : String(entry.targets || "").split(",").map(value => value.trim()));
    return Array.from(new Set(ips.filter(Boolean)));
  }

  function reportTargetLabel(entry){
    const ips = reportTargetIps(entry);
    return ips.length ? ips.join(", ") : "-";
  }

  function renderReportLog(){
    const xlsxBtn = document.getElementById("integratedXlsxBtn");
    if(xlsxBtn && API.integratedReportUrl){
      xlsxBtn.href = API.integratedReportUrl();
    }
    const body = document.getElementById("reportLogBody");
    if(!body) return;
    if(reportLog.length === 0){
      body.innerHTML = `<tr class="empty-row"><td colspan="5">아직 생성된 리포트가 없습니다.</td></tr>`;
      return;
    }
    body.innerHTML = reportLog.map((r, i) => `<tr class="clickable" data-log-index="${i}" tabindex="0">
      <td class="mono">${escapeHtml(formatReportTimestamp(r.timestamp))}</td>
      <td class="mono">${escapeHtml(r.user)}</td>
      <td>${escapeHtml(r.kind)}</td>
      <td class="col-detail">${escapeHtml(reportTargetLabel(r))}</td>
      <td>${escapeHtml(r.scope)}</td>
    </tr>`).join("");

    body.querySelectorAll("tr[data-log-index]").forEach(tr => {
      const open = () => openReportViewModal(Number(tr.dataset.logIndex));
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", e => { if(e.key === "Enter") open(); });
    });
  }

  let reportViewIndex = -1;
  let reportViewEvidence = [];

  function buildReportCsv(entry){
    const esc = v => `"${String(v == null ? "" : v).replace(/"/g, '""')}"`;
    const rows = reportRows(entry);
    const lines = [
      "IP,호스트명,코드,항목명,상태,중요도,액션태그,디테일",
      ...rows.map(r => {
        const host = hostMeta(r.ip);
        return [r.ip, host.hostname, r.code, r.title, r.status, r.severity, r.action_tag, r.detail].map(esc).join(",");
      })
    ];
    if(reportViewEvidence.length){
      lines.push("","작업 증적 및 무결성","작업ID,유형,대상,무결성,사전점검,파일,SHA256,파일검증");
      reportViewEvidence.forEach(item=>{
        const preflight=item.preflight || {};
        (item.files || []).forEach(file=>lines.push([
          item.job_id,item.kind,(item.targets||[]).join(" "),
          item.integrity_ok?"검증 완료":"검증 실패",
          `${preflight.passed||0}/${preflight.total||0} 통과`,
          file.path,file.sha256,file.verified?"일치":"불일치"
        ].map(esc).join(",")));
      });
    }
    return lines.join("\r\n");
  }

  const REPORT_PREVIEW_DUMMY_ROWS = [
    {
      ip:"100.76.242.18",
      code:"U-44",
      domain:"UNIX",
      title:"syslog 로그 파일 접근 권한 설정",
      status:"취약",
      detail:"/var/log/messages 파일 권한이 0666으로 설정되어 그룹 및 기타 사용자의 쓰기 권한이 허용됩니다.",
      diag:{
        command:"ls -l /var/log/messages",
        output:
          "-rw-rw-rw- 1 root root 20489 Aug 20 14:03 /var/log/messages\n" +
          "# stat -c '%A %U %G %a' /var/log/messages\n" +
          "-rw-rw-rw- root root 666",
        file:{
          owner:"root",
          group:"root",
          permission:"0666 (-rw-rw-rw-)",
          path:"/var/log/messages"
        },
        rationale:
          "syslog 로그 파일(/var/log/messages)의 권한이 0666으로 설정되어 있어 소유자(root) 외의 그룹 및 기타 사용자에게도 쓰기 권한이 부여된 상태입니다.\n" +
          "로그 파일에 대한 쓰기 권한이 일반 사용자에게 열려 있으면, 침해 사고 발생 시 공격자가 자신의 흔적을 지우거나 로그를 위·변조하여 사고 분석을 방해할 수 있습니다.\n" +
          "또한 임의의 사용자가 대용량 데이터를 기록해 디스크를 고갈시키는 서비스 거부(DoS) 형태의 악용도 가능합니다.\n" +
          "KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준(U-44)에서는 로그 파일의 권한을 640 이하로 제한하고 소유자를 root로 유지할 것을 권고합니다.\n" +
          "현재 설정은 이 기준을 충족하지 못하므로 '취약'으로 판정합니다.\n" +
          "권한을 640으로 조정하고(`chmod 640 /var/log/messages`), 소유자·그룹을 root:root 로 정리한 뒤 logrotate 설정에서도 create 640 root root 를 명시해 재생성 시에도 기준이 유지되도록 조치가 필요합니다."
      }
    },
    {
      ip:"100.120.178.40",
      code:"U-44",
      domain:"UNIX",
      title:"syslog 로그 파일 접근 권한 설정",
      status:"양호",
      detail:"/var/log/messages 파일 소유자는 root이며 권한이 0640으로 설정되어 접근 권한 기준을 충족합니다.",
      diag:{
        command:"ls -l /var/log/messages",
        output:
          "-rw-r----- 1 root root 18122 Aug 21 09:11 /var/log/messages\n" +
          "# stat -c '%A %U %G %a' /var/log/messages\n" +
          "-rw-r----- root root 640",
        file:{
          owner:"root",
          group:"root",
          permission:"0640 (-rw-r-----)",
          path:"/var/log/messages"
        },
        rationale:
          "syslog 로그 파일(/var/log/messages)의 소유자와 그룹이 모두 root 로 지정되어 있으며, 권한이 0640 으로 설정되어 있습니다.\n" +
          "소유자(root)에게만 읽기·쓰기 권한이 있고 그룹(root)에는 읽기 권한만, 기타 사용자에게는 어떠한 권한도 부여되지 않은 상태입니다.\n" +
          "이는 KISA 기술적 취약점 분석·평가 기준(U-44)에서 권고하는 '로그 파일 권한 640 이하, 소유자 root' 조건을 정확히 만족합니다.\n" +
          "일반 사용자가 로그를 열람하거나 위·변조할 수 없으므로 침해 사고 발생 시 로그의 무결성이 보장되며, 사고 분석 근거로 활용할 수 있습니다.\n" +
          "logrotate 설정(/etc/logrotate.d/rsyslog)에서도 create 640 root root 가 명시되어 있어 로그 재생성 시에도 동일한 권한이 유지됩니다.\n" +
          "따라서 현재 설정은 기준을 충족하므로 '양호'로 판정하며, 추가 조치는 필요하지 않습니다."
      }
    }
  ];

  function extractFileInfo(rawString){
    const empty = { owner:null, group:null, permission:null, path:null };
    if(typeof rawString !== "string") return empty;

    const lines = rawString.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    for(const line of lines){
      const match = line.match(/^([bcdlps-][rwxStTs-]{9}[.+@]?)\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+\S+\s+\S+(?:\s+\S+)?\s+(.+)$/);
      if(match){
        return {
          permission:match[1], owner:match[2], group:match[3], path:match[4].trim()
        };
      }

      const statMatch = line.match(/^(?:[bcdlps-][rwxStTs-]{9}[.+@]?\s+)?(\S+)\s+(\S+)\s+([0-7]{3,4})\s+(\/.+)$/);
      if(statMatch){
        return {
          owner:statMatch[1], group:statMatch[2],
          permission:statMatch[3], path:statMatch[4].trim()
        };
      }
    }

    const ownerMatch = rawString.match(/(?:소유자(?:는|가)?|owner)\s*[=:]?\s*([A-Za-z0-9_.-]+)/i);
    const groupMatch = rawString.match(/(?:그룹(?:은|이)?|group)\s*[=:]?\s*([A-Za-z0-9_.-]+)/i);
    const permissionMatch = rawString.match(/(?:권한(?:은|이)?|perm(?:ission)?)\s*[=:]?\s*([0-7]{3,4}|[bcdlps-][rwxStTs-]{9}[.+@]?)/i);
    const ownerGroupMatch = rawString.match(/(?:소유자(?:는|가)?|owner)\s*[=:]?\s*([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)/i);
    const pathMatch = rawString.match(/(?:^|[\s("'=:])(\/[^\s,;|)"']+)/m);
    return {
      owner:ownerGroupMatch ? ownerGroupMatch[1] : (ownerMatch ? ownerMatch[1] : null),
      group:ownerGroupMatch ? ownerGroupMatch[2] : (groupMatch ? groupMatch[1] : null),
      permission:permissionMatch ? permissionMatch[1] : null,
      path:pathMatch ? pathMatch[1].replace(/[.:]+$/, "") : null
    };
  }

  function firstFileValue(...values){
    const value = values.find(item => item !== null && item !== undefined && String(item).trim() !== "");
    return value === undefined ? null : String(value).trim();
  }

  function extractVulnerableFiles(row, rawText){
    const d = (row && row.diag) || {};
    const supplied = [d.vulnerableFiles, d.vulnerable_files, row.vulnerableFiles, row.vulnerable_files, d.files]
      .flatMap(value => Array.isArray(value) ? value : (value ? [value] : []))
      .map(value => typeof value === "string" ? value : firstFileValue(value.path, value.filePath))
      .filter(Boolean);
    const parsed = [];
    const pathPattern = /(?:^|[\s("'=:])(\/[^\s,;|)"']+)/gm;
    let match;
    while((match = pathPattern.exec(rawText || "")) !== null){
      parsed.push(match[1].replace(/[.:]+$/, ""));
    }
    return Array.from(new Set([...supplied, ...parsed]));
  }

  function normalizeReportDiag(row){
    const d = (row && row.diag) || {};
    const f = d.file || row.file || {};
    const rawDetail = typeof row.detail === "string" ? row.detail.trim() : "";
    const rawOutput = [d.output, rawDetail, d.command].filter(value => typeof value === "string" && value.trim()).join("\n");
    const parsedFile = extractFileInfo(rawOutput);
    const vulnerableFiles = extractVulnerableFiles(row, rawOutput);
    const fileEvidence = {
      "소유자":firstFileValue(f.owner, d.owner, row.owner, parsedFile.owner),
      "그룹":firstFileValue(f.group, d.group, row.group, parsedFile.group),
      "권한":firstFileValue(f.permission, d.permission, row.permission, parsedFile.permission),
      "파일 경로":firstFileValue(f.path, f.filePath, d.filePath, row.filePath, parsedFile.path)
    };
    Object.keys(fileEvidence).forEach(key => {
      if(fileEvidence[key] === null) delete fileEvidence[key];
    });
    const evidenceFields = [
      [row, "evidence_data"], [row, "evidenceData"],
      [d, "evidence_data"], [d, "evidenceData"]
    ];
    const suppliedEvidenceField = evidenceFields.find(([source, key]) =>
      source && Object.prototype.hasOwnProperty.call(source, key)
    );
    const suppliedEvidence = suppliedEvidenceField ? suppliedEvidenceField[0][suppliedEvidenceField[1]] : undefined;
    const hasSuppliedEvidence = suppliedEvidenceField !== undefined;
    const evidenceData = hasSuppliedEvidence
      ? (suppliedEvidence && typeof suppliedEvidence === "object" && !Array.isArray(suppliedEvidence) ? suppliedEvidence : {})
      : (Object.keys(fileEvidence).length
          ? fileEvidence
          : (vulnerableFiles.length ? { "취약한 파일 목록":vulnerableFiles } : {}));
    const resolvedOutput = d.output || rawDetail || "점검 명령 결과가 수집되지 않았습니다.";

    let rationale = typeof d.rationale === "string" ? d.rationale.trim() : "";
    if(!rationale){
      const statusText = isGoodStatus(row.status) ? "양호" : "취약";
      const impactText = typeof row.impact === "string" ? row.impact.trim() : "";
      const parts = [`KISA 기준 점검 결과 '${statusText}'으로 판정되었습니다.`];
      if(impactText) parts.push(impactText);
      if(rawDetail && rawDetail !== resolvedOutput.trim()){
        parts.push(`점검 근거: ${rawDetail}`);
      }
      rationale = parts.join("\n");
    }

    return {
      command:d.command || "ls -l <점검 대상 파일>",
      output:resolvedOutput,
      evidenceData,
      rationale
    };
  }

  function reportCheckCategory(row){
    const explicit = firstFileValue(
      row.category, row.check_category, row.checkCategory, row.item_category,
      row.diag && row.diag.category
    );
    if(explicit) return explicit;

    const code = String(row.code || "").trim().toUpperCase();
    const number = Number((code.match(/(\d+)$/) || [])[1]);
    if(code.startsWith("U-") && number){
      if(number <= 13) return "계정 관리";
      if(number <= 33) return "파일 및 디렉터리 관리";
      if(number <= 63) return "서비스 관리";
      if(number === 64) return "패치 관리";
      return "로그 관리";
    }
    if(code.startsWith("WEB-") && number){
      if(number <= 3) return "계정 관리";
      if(number <= 24) return "서비스 관리";
      if(number === 25) return "패치 관리";
      return "로그 관리";
    }
    if(code.startsWith("D-") && number){
      if(number <= 8) return "계정 및 권한 관리";
      if(number <= 24) return "접근 및 옵션 관리";
      if(number === 25) return "패치 관리";
      return "로그 관리";
    }
    return "기타";
  }

  function renderReportCategory(category){
    const label = String(category || "기타").trim();
    const compactLength = label.replace(/\s/g, "").length;
    if(compactLength <= 5){
      return `<span class="report-category-line">${escapeHtml(label)}</span>`;
    }

    const knownLines = {
      "계정 관리":["계정", "관리"],
      "파일 및 디렉터리 관리":["파일 및", "디렉터리", "관리"],
      "서비스 관리":["서비스", "관리"],
      "패치 관리":["패치", "관리"],
      "로그 관리":["로그", "관리"],
      "계정 및 권한 관리":["계정 및", "권한 관리"],
      "접근 및 옵션 관리":["접근 및", "옵션 관리"]
    };
    let lines = knownLines[label];
    if(!lines){
      const words = label.split(/\s+/).filter(Boolean);
      if(words.length > 1){
        lines = words.reduce((result, word) => {
          const current = result[result.length - 1];
          if(current && `${current}${word}`.replace(/\s/g, "").length <= 4){
            result[result.length - 1] = `${current} ${word}`;
          } else {
            result.push(word);
          }
          return result;
        }, []);
      } else {
        const suffix = ["관리", "설정", "점검"].find(value => label.endsWith(value) && label.length > value.length);
        lines = suffix ? [label.slice(0, -suffix.length), suffix] : [label];
      }
    }
    return lines.map(line => `<span class="report-category-line">${escapeHtml(line.trim())}</span>`).join("");
  }

  function reportCodeClass(code){
    const domain = domainOfCode(String(code || ""));
    return `report-code-${domain.toLowerCase()}`;
  }

  function formatTerminalHTML(cmdString, outputString) {
    const parts = (cmdString || "").trim().split(' ');
    let cmd = [];
    let param = [];
    let foundParam = false;

    for(let i = 0; i < parts.length; i++) {
      if(!foundParam) {
        if(i === 0 || parts[i].startsWith('-')) {
          cmd.push(parts[i]);
        } else {
          foundParam = true;
          param.push(parts[i]);
        }
      } else {
        param.push(parts[i]);
      }
    }

    let html = `<span class="prompt">$</span> <span class="command">${escapeHtml(cmd.join(' '))}</span>`;
    if(param.length > 0) {
      html += ` <span class="param">${escapeHtml(param.join(' '))}</span>`;
    }
    html += `<br><span class="output">${escapeHtml(outputString)}</span>`;
    return html;
  }

  function evidenceValueText(value){
    if(value === null || value === undefined || value === "") return "-";
    if(Array.isArray(value)) return value.map(evidenceValueText).join(", ");
    if(typeof value === "object"){
      const nestedEntries = Object.entries(value);
      if(nestedEntries.length === 0) return "-";
      return nestedEntries
        .map(([key, nestedValue]) => `${key}: ${evidenceValueText(nestedValue)}`)
        .join(" · ");
    }
    return String(value);
  }

  function isRiskyEvidence(key, value){
    const label = String(key || "");
    const text = evidenceValueText(value).trim();
    if(/취약|설정\s*안\s*됨|미설정|기준\s*미달|위반/i.test(text)) return true;
    if(/(?:권한|permission)/i.test(label)){
      const mode = text.match(/(?:^|\D)0?([0-7]{3})(?:\D|$)/);
      if(mode){
        const [, digits] = mode;
        if((Number(digits[1]) & 2) || (Number(digits[2]) & 2)) return true;
      }
    }
    if(/everyone/i.test(label) && /허용|allow|full/i.test(text)) return true;
    if(/(?:할당된\s*)?(?:롤|role)/i.test(label) && /(?:^|\W)DBA(?:\W|$)/i.test(text)) return true;
    return /directory\s*listing/i.test(label) && /^(?:on|enabled|활성(?:화|됨)?)$/i.test(text);
  }

  function renderEvidenceData(data){
    const entries = data && typeof data === "object" && !Array.isArray(data)
      ? Object.entries(data)
      : [];
    if(entries.length === 0){
      return `<p class="report-evidence-empty">수집된 증적 자료 없음</p>`;
    }
    return `<ul class="report-evidence-list">${entries.map(([key, value]) => {
      const valueText = evidenceValueText(value);
      const riskClass = isRiskyEvidence(key, value) ? " is-risk" : "";
      return `<li><span class="report-evidence-key">${escapeHtml(key)}</span><span class="report-evidence-value${riskClass}">${escapeHtml(valueText)}</span></li>`;
    }).join("")}</ul>`;
  }

  function renderReportDiagCell(diag){
    return `<div class="report-diag">
        <section class="report-diag-block">
          <h4 class="report-diag-title">[진단 내용]</h4>
          <ol class="report-diag-list">
            <li>
              <span class="report-diag-step">점검 명령어 및 결과</span>
              <div class="terminal" aria-label="점검 명령어 및 결과">${formatTerminalHTML(diag.command, diag.output)}</div>
            </li>
            <li class="report-evidence-block">
              <span class="report-diag-step">점검 현황 (증적 자료)</span>
              ${renderEvidenceData(diag.evidenceData)}
            </li>
          </ol>
        </section>
        <section class="report-diag-block">
          <h4 class="report-diag-title">[진단 결과]</h4>
          <div class="report-diag-sub">
            <span class="report-diag-step">진단 근거</span>
            <blockquote class="report-diag-quote">${escapeHtml(diag.rationale)}</blockquote>
          </div>
        </section>
      </div>`;
  }

  function buildReportPreviewData(entry){
    const sourceRows = reportRows(entry);
    const rows = (sourceRows.length ? sourceRows : REPORT_PREVIEW_DUMMY_ROWS).map(row => ({
      ip:row.ip || "-",
      code:String(row.code || "-").trim(),
      category:reportCheckCategory(row),
      title:row.title || "-",
      status:isGoodStatus(row.status) ? "양호" : "취약",
      detail:row.detail || "진단 결과 상세 내용이 없습니다.",
      diag:normalizeReportDiag(row)
    }));
    return {
      createdBy:entry.user || currentUser || "admin",
      createdAt:formatReportTimestamp(entry.timestamp || new Date().toISOString()),
      kind:entry.kind || "통합 보안 점검",
      targets:sourceRows.length
        ? reportTargetLabel(entry)
        : Array.from(new Set(rows.map(row => row.ip))).join(", "),
      scope:entry.scope || "전체 출력",
      rows
    };
  }

  function renderReportPreview(data){
    document.getElementById("reportPaperCreatedBy").textContent = data.createdBy;
    document.getElementById("reportPaperCreatedAt").textContent = data.createdAt;
    document.getElementById("reportPaperKind").textContent = data.kind;
    document.getElementById("reportPaperScope").textContent = data.scope;
    document.getElementById("reportPaperTargets").textContent = data.targets;
    document.getElementById("reportPaperCount").textContent = `총 ${data.rows.length}건`;
    renderReportEvidence(data.evidence || []);
    renderReportDomainSummary(data.rows);

    const body = document.getElementById("reportPreviewTableBody");
    if(data.rows.length === 0){
      body.innerHTML = `<tr><td class="report-empty-cell" colspan="6">표시할 점검 결과가 없습니다.</td></tr>`;
      return;
    }

    body.innerHTML = data.rows.map(row => {
      const isGood = row.status === "양호";
      return `<tr>
        <td class="report-cell-center mono">${escapeHtml(row.ip)}</td>
        <td class="report-cell-center mono report-code"><span class="report-code-tag ${reportCodeClass(row.code)}">${escapeHtml(row.code)}</span></td>
        <td class="report-cell-center report-category">${renderReportCategory(row.category)}</td>
        <td class="report-item-title">${escapeHtml(row.title)}</td>
        <td class="report-cell-center">
          <span class="report-status-badge ${isGood ? "good" : "vuln"}">${escapeHtml(row.status)}</span>
        </td>
        <td class="report-diag-cell">${renderReportDiagCell(row.diag)}</td>
      </tr>`;
    }).join("");
  }

  function renderReportDomainSummary(rows){
    const container = document.getElementById("reportDomainSummary");
    const totalsEl = document.getElementById("reportDomainTotals");
    if(!container || !totalsEl) return;

    const domains = [
      { key:"UNIX", cls:"domain-card-unix" },
      { key:"WEB",  cls:"domain-card-web"  },
      { key:"DBMS", cls:"domain-card-dbms" },
    ];

    const total = rows.length;
    const vulnAll = rows.filter(r => r.status === "취약").length;
    const goodAll = rows.filter(r => r.status === "양호").length;
    const pendingAll = rows.filter(r => r.status === "취약" && (itemMeta[r.code] || {}).action_tag === "승인요청").length;
    const autoAll = vulnAll - pendingAll;
    const affectedHosts = new Set(rows.filter(r => r.status === "취약").map(r => r.ip)).size;
    const allHosts = new Set(rows.map(r => r.ip)).size;

    const initialScore = total ? Math.round((goodAll / total) * 1000) / 10 : 0;
    const autoScore = total ? Math.round(((goodAll + autoAll) / total) * 1000) / 10 : 0;
    const finalScore = total ? Math.round(((goodAll + autoAll + pendingAll) / total) * 1000) / 10 : 0;

    totalsEl.style.gridTemplateColumns = "repeat(6, minmax(0, 1fr))";
    totalsEl.innerHTML = `
      <div class="dt-item"><span class="dt-l">전체 점검 항목</span><span class="dt-v">${total}<em>건</em></span><span class="dt-sub">대상 서버 ${allHosts}대</span></div>
      <div class="dt-item vuln"><span class="dt-l">취약 항목</span><span class="dt-v">${vulnAll}<em>건</em></span><span class="dt-sub">영향 서버 ${affectedHosts}대</span></div>
      <div class="dt-item appr"><span class="dt-l">승인/자동조치</span><span class="dt-v">${pendingAll}<em>/${autoAll}건</em></span><span class="dt-sub">조치 대기</span></div>
      <div class="dt-item good"><span class="dt-l">점검 점수</span><span class="dt-v" style="color:var(--vuln-text)">${initialScore}<em>점</em></span><span class="dt-track"><span style="width:${initialScore}%; background:linear-gradient(90deg,var(--vuln),#e74c3c)"></span></span></div>
      <div class="dt-item"><span class="dt-l">자동조치 후 점수</span><span class="dt-v" style="color:#3b82f6">${autoScore}<em>점</em></span><span class="dt-track"><span style="width:${autoScore}%; background:linear-gradient(90deg,#60a5fa,#3b82f6)"></span></span></div>
      <div class="dt-item good"><span class="dt-l">승인조치 후 점수</span><span class="dt-v">${finalScore}<em>점</em></span><span class="dt-track"><span style="width:${finalScore}%"></span></span></div>`;

    container.innerHTML = domains.filter(({ key }) => rows.some(row => domainOfCode(row.code) === key)).map(({ key, cls }) => {
      const dRows = rows.filter(row => domainOfCode(row.code) === key);
      const vulnRows = dRows.filter(r => r.status === "취약");
      const vuln = vulnRows.length;
      const rate = dRows.length ? Math.round((vuln / dRows.length) * 1000) / 10 : 0;

      const categoryDefinitions = domainVulnerabilityCategories(key);
      const categories = categoryDefinitions.map(category => ({
        label:category.label,
        count:vulnRows.filter(row => {
          const number = Number((String(row.code || "").match(/(\d+)$/) || [])[1]) || 0;
          return category.match(number);
        }).length
      }));
      const validCategories = categories.filter(c => c.count > 0);
      let categoryChart = '';
      if(validCategories.length === 0){
        categoryChart = '<div style="height:100%; display:flex; align-items:center; justify-content:center; color:var(--text-3); font-size:12px;">취약 항목 없음</div>';
      }else{
        const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
        const totalVuln = validCategories.reduce((acc, c) => acc + c.count, 0);
        let offset = 0;
        let circles = '';
        validCategories.forEach((c, i) => {
          const dash = (c.count / totalVuln) * 100;
          const gap = 100 - dash;
          circles += `<circle cx="20" cy="20" r="15.915" fill="none" stroke="${colors[i % colors.length]}" stroke-width="6" stroke-dasharray="${dash} ${gap}" stroke-dashoffset="${100 - offset}"></circle>`;
          offset += dash;
        });
        const svg = `<svg viewBox="0 0 40 40" style="width:70px; height:70px; transform: rotate(-90deg); overflow:visible;">
                       <circle cx="20" cy="20" r="15.915" fill="none" stroke="#f1f5f9" stroke-width="6"></circle>
                       ${circles}
                     </svg>`;
        const legend = validCategories.map((c, i) => `
          <div style="display:flex; justify-content:space-between; align-items:center; font-size:11px; margin-bottom:5px;">
            <span style="display:flex; align-items:center; gap:6px; color:var(--text-2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
              <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${colors[i % colors.length]}; flex-shrink:0;"></span>
              <span style="overflow:hidden; text-overflow:ellipsis;">${escapeHtml(c.label)}</span>
            </span>
            <b style="color:var(--text-1); margin-left:8px;">${c.count}</b>
          </div>
        `).join("");
        
        categoryChart = `
          <div style="display:flex; align-items:center; gap:16px; height:100%;">
            <div style="flex-shrink:0; width:70px; height:70px;">
              ${svg}
            </div>
            <div style="flex:1; min-width:0; display:flex; flex-direction:column; justify-content:center;">
              ${legend}
            </div>
          </div>
        `;
      }

      const approve = vulnRows.filter(r => (itemMeta[r.code] || {}).action_tag === "승인요청").length;
      const auto = vuln - approve;
      const domainHosts = new Set(dRows.map(r => r.ip)).size;
      const affected = new Set(vulnRows.map(r => r.ip)).size;
      const clean = vuln === 0;

      return '<div class="domain-card ' + cls + '" style="pointer-events: none; flex: 1 1 0; min-width: 0;">' +
        '<span class="domain-card-top">' +
          '<span class="domain-card-label">' + key + '</span>' +
          '<span class="domain-card-hosts ' + (clean ? "zero" : "") + '">서버 <b>' + affected + '</b>/' + domainHosts + '대 영향</span>' +
        '</span>' +
        '<div class="domain-rank-chart" style="margin-top: 12px; display: block; box-sizing: border-box;">' + categoryChart + '</div>' +
        '<span class="domain-card-foot">' +
          (clean
            ? '<span class="dc-chip clear">조치 완료 — 취약 없음</span>'
            : '<span class="dc-chip approve">승인 필요 <b>' + approve + '</b>건</span><span class="dc-chip auto">자동조치 <b>' + auto + '</b>건</span>') +
        '</span>' +
      '</div>';
    }).join("");
  }

  function evidenceJobsForReport(entry){
    const targetIps=new Set(reportTargetIps(entry));
    const targetHosts=new Set(Array.from(targetIps).map(ip=>(registeredIps.find(row=>row.ip===ip)||{}).hostname).filter(Boolean));
    const selected=[];const covered=new Set();
    evidenceJobs.forEach(job=>{
      const ips=(job.preflight && job.preflight.hosts || []).map(host=>host.ip);
      const matches=ips.filter(ip=>targetIps.has(ip) && !covered.has(ip));
      const hostMatch=(job.targets || []).some(host=>targetHosts.has(host));
      if(matches.length || (hostMatch && selected.length===0)){
        selected.push(job);matches.forEach(ip=>covered.add(ip));
      }
    });
    return selected.slice(0,Math.max(1,targetIps.size));
  }

  function renderReportEvidence(items){
    const count=document.getElementById("reportEvidenceCount");
    const container=document.getElementById("reportEvidenceSummary");
    if(!count || !container)return;
    count.textContent=items.length ? `증적 ${items.length}건` : "연결 증적 없음";
    if(!items.length){
      container.innerHTML='<p class="report-evidence-empty">선택한 대상과 연결된 작업 증적이 없습니다.</p>';return;
    }
    container.innerHTML=items.map(item=>{
      const preflight=item.preflight || {};const files=item.files || [];
      const fileRows=files.slice(0,8).map(file=>`<li><span>${file.verified?"✓":"!"} ${escapeHtml(file.path)}</span><code>${escapeHtml(file.sha256)}</code></li>`).join("");
      const more=files.length>8?`<li class="report-evidence-more">외 ${files.length-8}개 파일은 원본 증적 ZIP에 포함</li>`:"";
      const logs=(item.log_tail || []).slice(-6).map(line=>escapeHtml(line)).join("\n");
      return `<article class="report-evidence-job">
        <div class="report-evidence-job-head"><strong>작업 ${escapeHtml(item.job_id)}</strong><span class="${item.integrity_ok?"verified":"invalid"}">${item.integrity_ok?"SHA-256 검증 완료":"무결성 검증 실패"}</span></div>
        <dl><div><dt>유형</dt><dd>${escapeHtml(item.kind || "-")}</dd></div><div><dt>대상</dt><dd>${escapeHtml((item.targets||[]).join(", ") || "-")}</dd></div>
        <div><dt>수집 시각</dt><dd>${escapeHtml(formatTimestamp((item.collected_at||0)*1000,true))}</dd></div>
        <div><dt>사전점검</dt><dd>${preflight.passed || 0}/${preflight.total || 0} 통과</dd></div></dl>
        <h4>수집 파일 및 SHA-256</h4><ul>${fileRows}${more}</ul>
        <h4>실행 로그 요약</h4><pre>${logs || "기록 없음"}</pre>
      </article>`;
    }).join("");
  }

  async function openReportViewModal(index){
    reportViewIndex = index;
    const entry = reportLog[index];
    if(!entry) return;
    document.getElementById("reportViewTitle").textContent = "리포트 미리보기";
    document.getElementById("reportViewMeta").textContent = `${formatReportTimestamp(entry.timestamp)} · ${entry.user} 생성`;
    document.getElementById("reportSaveFormat").value = "pdf";
    reportViewEvidence=[];
    const saveButton=document.getElementById("reportViewSave");saveButton.disabled=true;
    const data=buildReportPreviewData(entry);data.evidence=[];
    renderReportPreview(data);
    document.getElementById("reportViewModalOverlay").classList.remove("hidden");
    const jobsForReport=evidenceJobsForReport(entry);
    if(jobsForReport.length){
      document.getElementById("reportEvidenceCount").textContent="증적 불러오는 중";
      try{data.evidence=await Promise.all(jobsForReport.map(job=>API.getEvidenceSummary(job.id)));}
      catch(_error){data.evidence=[];}
      reportViewEvidence=data.evidence;
      renderReportEvidence(data.evidence);
    }
    saveButton.disabled=false;
  }

  function closeReportViewModal(){
    reportViewEvidence=[];
    document.getElementById("reportViewModalOverlay").classList.add("hidden");
  }

  function printReportAsPdf(){
    const area = document.getElementById("printArea");
    const paper = document.getElementById("reportPreviewPaper");
    area.innerHTML = paper ? paper.outerHTML : "";
    document.body.classList.add("printing");
    const cleanup = () => {
      document.body.classList.remove("printing");
      area.innerHTML = "";
      window.removeEventListener("afterprint", cleanup);
    };
    window.addEventListener("afterprint", cleanup);
    window.print();
  }

  function downloadCsv(entry){
    const content = buildReportCsv(entry);
    const filenameSafe = reportTargetLabel(entry).replace(/[^\w가-힣-]+/g, "_").slice(0, 40);
    const blob = new Blob(["\uFEFF", content], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kisa-report_${filenameSafe}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function initReportViewModal(){
    document.getElementById("reportViewClose").addEventListener("click", closeReportViewModal);
    document.getElementById("reportViewModalOverlay").addEventListener("click", e => {
      if(e.target.id === "reportViewModalOverlay") closeReportViewModal();
    });
    document.getElementById("reportViewSave").addEventListener("click", () => {
      const entry = reportLog[reportViewIndex];
      if(!entry) return;
      const format = document.getElementById("reportSaveFormat").value;
      if(format === "pdf"){
        console.log("PDF 저장 실행");
        printReportAsPdf();
      }else{
        console.log("CSV 저장 실행");
        downloadCsv(entry);
      }
    });
  }

  function initAccountPage(){
    document.getElementById("pwChangeBtn").addEventListener("click", async () => {
      const current = document.getElementById("pwCurrent").value;
      const next = document.getElementById("pwNew").value;
      const confirm = document.getElementById("pwConfirm").value;

      if(!current || !next || !confirm){
        alert("모든 항목을 입력해 주세요.");
        return;
      }
      if(next.length < 8){
        alert("새 비밀번호는 8자 이상이어야 합니다.");
        return;
      }
      if(next !== confirm){
        alert("새 비밀번호와 확인이 일치하지 않습니다.");
        return;
      }
      try{
        await API.changePassword({ loginId: currentLoginId, current, next });
      }catch(error){
        alert(error.message || "비밀번호 변경에 실패했습니다.");
        return;
      }
      alert("비밀번호가 변경되었습니다.");
      document.getElementById("pwCurrent").value = "";
      document.getElementById("pwNew").value = "";
      document.getElementById("pwConfirm").value = "";
    });
  }

  function initAccountNav(){
    const accountButton = document.getElementById("accountNameBtn");
    const accountMenu = document.getElementById("accountMenu");

    accountButton.addEventListener("click", event => {
      event.stopPropagation();
      const willOpen = accountMenu.classList.contains("hidden");
      accountMenu.classList.toggle("hidden", !willOpen);
      accountButton.setAttribute("aria-expanded", String(willOpen));
    });

    document.getElementById("accountInfoMenuBtn").addEventListener("click", () => {
      closeAccountMenu();
      openAccountVerifyModal();
    });

    document.getElementById("passwordChangeMenuBtn").addEventListener("click", () => {
      closeAccountMenu();
      showAccountPanel("password");
    });

    document.addEventListener("click", event => {
      if(!event.target.closest(".account-menu-wrap")) closeAccountMenu();
    });
    document.addEventListener("keydown", event => {
      if(event.key === "Escape"){
        closeAccountMenu();
        closeAccountVerifyModal();
      }
    });
  }

  function closeAccountMenu(){
    const menu = document.getElementById("accountMenu");
    const button = document.getElementById("accountNameBtn");
    if(menu) menu.classList.add("hidden");
    if(button) button.setAttribute("aria-expanded", "false");
  }

  function showAccountPanel(panel){
    const showingInfo = panel === "info";
    document.getElementById("accountInfoPanel").classList.toggle("hidden", !showingInfo);
    document.getElementById("passwordChangePanel").classList.toggle("hidden", showingInfo);
    if(showingInfo){
      const acctId = document.getElementById("acctId");
      if(acctId) acctId.value = currentLoginId || "";
      document.getElementById("acctName").value = currentUserProfile ? currentUserProfile.username || "" : "";
      document.getElementById("acctEmail").value = currentUserProfile ? currentUserProfile.email || "" : "";
      document.getElementById("acctDept").value = currentUserProfile ? currentUserProfile.organization || "" : "";
    }
    showView("account");
  }

  function openAccountVerifyModal(){
    const overlay = document.getElementById("accountVerifyModalOverlay");
    const password = document.getElementById("accountVerifyPassword");
    password.value = "";
    overlay.classList.remove("hidden");
    setTimeout(() => password.focus(), 0);
  }

  function closeAccountVerifyModal(){
    const overlay = document.getElementById("accountVerifyModalOverlay");
    const password = document.getElementById("accountVerifyPassword");
    if(overlay) overlay.classList.add("hidden");
    if(password) password.value = "";
  }

  function initAccountVerification(){
    async function verifyAndOpen(){
      const password = document.getElementById("accountVerifyPassword").value;
      if(!password){
        alert("비밀번호를 입력해 주세요.");
        return;
      }
      try{
        await API.login(currentLoginId, password);
      }catch(error){
        alert(error.message || "비밀번호 확인에 실패했습니다.");
        return;
      }
      closeAccountVerifyModal();
      showAccountPanel("info");
    }

    document.getElementById("accountVerifyConfirm").addEventListener("click", verifyAndOpen);
    document.getElementById("accountVerifyCancel").addEventListener("click", closeAccountVerifyModal);
    document.getElementById("accountVerifyPassword").addEventListener("keydown", event => {
      if(event.key === "Enter") verifyAndOpen();
    });
    document.getElementById("accountVerifyModalOverlay").addEventListener("click", event => {
      if(event.target.id === "accountVerifyModalOverlay") closeAccountVerifyModal();
    });
  }

  function initFilterBar(){
    document.querySelectorAll("#domainFilterGroup .seg-btn").forEach(btn => {
      btn.addEventListener("click", () => setFilters(btn.dataset.domain));
    });
    document.getElementById("filterResetBtn").addEventListener("click", () => setFilters("ALL"));
  }

  function renderAll(){
    renderNavStats();
    renderCheckNotifications();
    renderSecurityScore();
    renderIpTable();
    renderCheckView();
    renderActionByIp();
    renderActionByVuln();
    renderReportLog();
  }

  document.addEventListener("DOMContentLoaded", () => {
    initAppDialog();
    initSshApprovalModal();
    initSshCaControls();
    initCheckNotifications();
    initLogin();
    initLogout();
    initNav();
    initTabGroups();
    initIpRegistration();
    initDomainRunModal();
    initCheckApprovals();
    initActionReports();
    initReportModal();
    initReportViewModal();
    initAccountNav();
    initAccountVerification();
    initAccountPage();
    initFilterBar();
    initDbResults();
  });
})();
