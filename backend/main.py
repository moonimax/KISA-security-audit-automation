"""
main.py
KISA 보안점검 콘솔 백엔드 API (FastAPI).

프론트엔드(frontend/api.js)가 호출하는 REST API를 제공한다.
  GET  /api/results            저장된 점검 결과 전체 조회 (host로 필터 가능)
  POST /api/results             점검 결과 JSON을 DB에 저장(Ansible/점검 스크립트 등이 호출)

실행:
  uvicorn backend.main:app --reload --port 8000
"""
import ipaddress
import json
import re
from typing import Any, Optional

from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import ssap_reports

from . import db, inventory_sync, jobs, security
from .runtime import RUNTIMES, domain_for_code

app = FastAPI(title="KISA 보안점검 콘솔 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup() -> None:
    db.init_db()
    security.init()
    security.rebuild_known_hosts()

class SaveResultsRequest(BaseModel):
    host: str
    ip: Optional[str] = None
    results: list[dict[str, Any]]

class LoginRequest(BaseModel):
    login_id: str
    password: str

class ChangePasswordRequest(BaseModel):
    login_id: str
    current_password: str
    new_password: str

class ReportLogRequest(BaseModel):
    timestamp: str = ""
    user: str = ""
    kind: str
    context: str = ""
    targets: str = ""
    scope: str = ""
    isCode: bool = False
    targetList: list[str] = Field(default_factory=list)
    scopeRaw: str = "all"

@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    user = db.authenticate_user(payload.login_id, payload.password)
    if user is None:
        raise HTTPException(401, "아이디 또는 비밀번호가 올바르지 않습니다.")
    token=security.create_session(user["login_id"])
    return {"ok": True, "user": user, "token": token}

def _session_login_id(authorization: Optional[str]) -> str:
    token=authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
    login_id=security.session_user(token)
    if not login_id:
        raise HTTPException(401,"로그인이 만료되었습니다. 다시 로그인하세요.")
    return login_id

@app.post("/api/auth/logout")
def logout(authorization: Optional[str]=Header(default=None)) -> dict[str,bool]:
    token=authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
    security.revoke_session(token)
    return {"ok":True}

@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordRequest) -> dict[str, bool]:
    if len(payload.new_password) < 8:
        raise HTTPException(400, "새 비밀번호는 8자 이상이어야 합니다.")
    changed = db.change_password(
        payload.login_id, payload.current_password, payload.new_password
    )
    if not changed:
        raise HTTPException(401, "현재 비밀번호가 올바르지 않습니다.")
    return {"ok": True}

@app.get("/api/results")
def get_results(host: Optional[str] = None) -> list[dict[str, Any]]:
    """DB에 저장된 점검 결과를 JSON 배열로 반환한다. ?host=<hostname> 으로 필터 가능."""
    return db.fetch_results(host=host)

@app.get("/api/reports/integrated.xlsx")
def download_integrated_report(host: Optional[str] = None) -> Response:
    """DB에 저장된 점검 결과를 디자인된 통합 엑셀(.xlsx) 리포트로 내려준다.

    대시보드 '리포트 기록' 화면의 '통합 엑셀 리포트(.xlsx) 다운로드' 버튼이 호출한다.
    ?host=<hostname> 을 주면 해당 호스트 결과만 담는다.
    """
    results = db.fetch_results(host=host)

    evidence=[]
    for job in jobs.list_jobs(50):
        if not job.get("evidence_available") or (host and host not in job.get("targets",[])):continue
        try:evidence.append(security.evidence_summary(job["id"]))
        except (OSError,ValueError,json.JSONDecodeError):continue
    content = ssap_reports.build_report_bytes(results,evidence)
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d_%H%M")
    filename = f"ssap_reports_{stamp}.xlsx"
    return Response(
        content=content,
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',

            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
        },
    )

@app.get("/api/check-runs")
def get_check_runs(limit: int = 100) -> list[dict[str, Any]]:
    """재점검을 포함한 최근 점검/조치 실행 이력을 반환한다."""
    return db.fetch_check_runs(limit=max(1, min(limit, 500)))

@app.get("/api/report-logs")
def get_report_logs(limit: int = 500) -> list[dict[str, Any]]:
    """리포트 생성 기록을 점검 이력처럼 DB에서 최신순으로 조회한다."""
    return db.fetch_report_logs(limit=max(1, min(limit, 1000)))

@app.post("/api/report-logs")
def post_report_log(payload: ReportLogRequest) -> list[dict[str, Any]]:
    """리포트 생성 기록을 저장하고 갱신된 최신 기록을 반환한다."""
    db.add_report_log(payload.dict())
    return db.fetch_report_logs(limit=500)

@app.post("/api/results")
def post_results(payload: SaveResultsRequest) -> dict[str, Any]:
    """점검 결과 JSON(예: reports/<host>_check.json 내용)을 받아 DB에 저장한다."""
    saved = db.save_results(host=payload.host, results=payload.results, ip=payload.ip)
    return {"ok": True, "saved": saved}

class HostIn(BaseModel):
    ip: str
    hostname: str
    domains: list[str] = Field(default_factory=lambda: ["UNIX"])

@app.get("/api/hosts")
def list_hosts() -> list[dict[str, Any]]:
    hosts=db.list_hosts()
    for host in hosts:
        host["ssh_identity"]=security.public_identity(host["ip"])
        host["connection_status"]=security.status(host["ip"])
    return hosts

@app.post("/api/hosts")
def add_host(payload: HostIn) -> dict[str, Any]:
    try:
        ipaddress.ip_address(payload.ip)
    except ValueError as exc:
        raise HTTPException(400, "올바른 IPv4 또는 IPv6 주소를 입력하세요.") from exc
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", payload.hostname):
        raise HTTPException(400, "호스트명은 영문자, 숫자, 점, 밑줄, 하이픈만 사용할 수 있습니다.")
    domains = list(dict.fromkeys(domain.strip().upper() for domain in payload.domains)) or ["UNIX"]
    if any(domain not in RUNTIMES for domain in domains):
        raise HTTPException(400, "지원하지 않는 진단영역이 포함되어 있습니다.")
    host = db.add_host(ip=payload.ip, hostname=payload.hostname, domains=domains)
    if host is None:
        return {"ok": False, "reason": "duplicate"}
    inventory_sync.sync_inventory()
    return {"ok": True, "entry": host}

@app.delete("/api/hosts/{ip}")
def remove_host(ip: str) -> dict[str, Any]:
    ok = db.remove_host(ip)
    if ok:
        security.remove_host(ip)
        inventory_sync.sync_inventory()
    return {"ok": ok}

class CheckJobIn(BaseModel):
    ips: list[str]
    domains: list[str] = Field(default_factory=lambda: ["ALL"])

@app.post("/api/jobs/check")
def start_check_job(payload: CheckJobIn) -> dict[str, str]:
    """선택한 IP들에 대해 점검(check.yml) + 자동조치(audit.yml)를 실행한다."""
    requested_domains = [domain.strip().upper() for domain in payload.domains]
    if not requested_domains:
        requested_domains = ["ALL"]
    if any(domain not in {"ALL", "UNIX", "WEB", "DBMS"} for domain in requested_domains):
        raise HTTPException(400, "지원하지 않는 진단영역이 포함되어 있습니다.")
    domains = ["ALL"] if "ALL" in requested_domains else list(dict.fromkeys(requested_domains))

    entries_by_ip = {host["ip"]: host for host in db.list_hosts()}
    selected_hosts = []
    for ip in payload.ips:
        host = entries_by_ip.get(ip)
        if not host:
            continue
        host_domains = host.get("domains") or ["UNIX"]
        if "ALL" not in domains and not any(domain in host_domains for domain in domains):
            continue
        selected_hosts.append((host["hostname"], ip, host_domains))

    if not selected_hosts:
        raise HTTPException(400, "선택한 진단영역에 등록된 IP가 없습니다.")
    try:
        job_id = jobs.start_check_job(selected_hosts, domains=domains)
    except jobs.HostBusyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"job_id": job_id}

@app.post("/api/jobs/check-only")
def start_check_only_job(payload: CheckJobIn) -> dict[str, str]:
    """선택한 IP에 자동조치 없이 점검 플레이북만 실행한다."""
    requested=[domain.strip().upper() for domain in payload.domains] or ["ALL"]
    if any(domain not in {"ALL","UNIX","WEB","DBMS"} for domain in requested):
        raise HTTPException(400,"지원하지 않는 진단영역이 포함되어 있습니다.")
    domains=["ALL"] if "ALL" in requested else list(dict.fromkeys(requested))
    entries={host["ip"]:host for host in db.list_hosts()}
    selected=[]
    for ip in payload.ips:
        host=entries.get(ip)
        if not host:continue
        host_domains=host.get("domains") or ["UNIX"]
        if "ALL" not in domains and not any(domain in host_domains for domain in domains):continue
        selected.append((host["hostname"],ip,host_domains))
    if not selected:
        raise HTTPException(400,"선택한 진단영역에 등록된 IP가 없습니다.")
    try:
        job_id=jobs.start_check_only_job(selected,domains=domains)
    except jobs.HostBusyError as exc:
        raise HTTPException(409,str(exc)) from exc
    return {"job_id":job_id}

class RemediateItem(BaseModel):
    ip: str
    code: str

class RemediateJobIn(BaseModel):
    items: list[RemediateItem]

@app.post("/api/jobs/remediate")
def start_remediate_job(payload: RemediateJobIn) -> dict[str, str]:
    """선택한 (IP, 코드) 항목들에 대해 승인조치(remediate_approved.yml) + 재점검(check.yml)을 실행한다."""
    entries_by_ip = {host["ip"]: host for host in db.list_hosts()}
    grouped: dict[str, list[str]] = {}
    ip_by_host: dict[str, str] = {}
    for item in payload.items:
        host = entries_by_ip.get(item.ip)
        if not host:
            continue
        hostname = host["hostname"]
        try:
            domain = domain_for_code(item.code)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if domain not in (host.get("domains") or ["UNIX"]):
            raise HTTPException(400, f"{item.ip}에는 {domain} 진단영역이 등록되어 있지 않습니다.")
        grouped.setdefault(hostname, []).append(item.code)
        ip_by_host[hostname] = item.ip

    if not grouped:
        raise HTTPException(400, "등록된 IP가 없습니다.")

    triples = [(host, ip_by_host[host], codes) for host, codes in grouped.items()]
    try:
        job_id = jobs.start_remediate_job(triples)
    except jobs.HostBusyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"job_id": job_id}


class HostKeyApprovalIn(BaseModel):
    trusted_fingerprint: str
    password: str

class SshCaActionIn(BaseModel):
    password: str

class PreflightIn(BaseModel):
    ips: list[str]

def _registered_ip(ip: str) -> None:
    if not any(host["ip"] == ip for host in db.list_hosts()):
        raise HTTPException(404, "등록된 서버를 찾을 수 없습니다.")

@app.post("/api/hosts/{ip}/ssh-key/scan")
def scan_ssh_key(ip: str) -> dict[str, Any]:
    _registered_ip(ip)
    try:
        security.scan(ip)
        return security.public_identity(ip)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(502, str(exc)) from exc

@app.post("/api/hosts/{ip}/ssh-key/approve")
def approve_ssh_key(
    ip: str,
    payload: HostKeyApprovalIn,
    authorization: Optional[str]=Header(default=None),
) -> dict[str, Any]:
    _registered_ip(ip)
    login_id=_session_login_id(authorization)
    if db.authenticate_user(login_id,payload.password) is None:
        current=security.identity(ip)
        security.record_identity_audit(
          ip,"approve",login_id,current.get("observed_fp") or "",
          payload.trusted_fingerprint,current.get("approved_fp") or "","reauth_failed")
        raise HTTPException(401,"관리자 비밀번호가 올바르지 않습니다.")
    try:
        security.approve(ip,payload.trusted_fingerprint,login_id)
        return security.public_identity(ip)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

@app.get("/api/hosts/{ip}/ssh-key/audit")
def get_ssh_key_audit(
    ip: str,
    authorization: Optional[str]=Header(default=None),
) -> list[dict[str,Any]]:
    _registered_ip(ip)
    _session_login_id(authorization)
    rows=security.identity_audit(ip)
    if security.identity(ip).get("status")!="trusted":
        for row in rows:
            row["observed_fp"]=row["trusted_fp"]=row["previous_fp"]=""
    return rows
@app.get("/api/ssh-ca/status")
def get_ssh_ca_status(
    authorization: Optional[str]=Header(default=None),
) -> dict[str,Any]:
    _session_login_id(authorization)
    return security.ca_status()

@app.post("/api/ssh-ca/initialize")
def initialize_ssh_ca(
    payload: SshCaActionIn,
    authorization: Optional[str]=Header(default=None),
) -> dict[str,Any]:
    login_id=_session_login_id(authorization)
    if db.authenticate_user(login_id,payload.password) is None:
        raise HTTPException(401,"관리자 비밀번호가 올바르지 않습니다.")
    try:return security.initialize_host_ca()
    except (ValueError,RuntimeError) as exc:raise HTTPException(409,str(exc)) from exc

@app.post("/api/hosts/{ip}/ssh-certificate/deploy")
def deploy_ssh_host_certificate(
    ip: str,
    payload: SshCaActionIn,
    authorization: Optional[str]=Header(default=None),
) -> dict[str,Any]:
    _registered_ip(ip)
    login_id=_session_login_id(authorization)
    if db.authenticate_user(login_id,payload.password) is None:
        current=security.identity(ip)
        security.record_identity_audit(
          ip,"cert_deploy",login_id,current.get("approved_fp") or "","","","reauth_failed")
        raise HTTPException(401,"관리자 비밀번호가 올바르지 않습니다.")
    try:return security.deploy_host_certificate(ip,login_id)
    except ValueError as exc:raise HTTPException(409,str(exc)) from exc
    except RuntimeError as exc:raise HTTPException(502,str(exc)) from exc



@app.post("/api/hosts/{ip}/connection-check")
def connection_check(ip: str) -> dict[str, Any]:
    _registered_ip(ip)
    return security.connection_check(ip)

@app.post("/api/preflight")
def run_preflight(payload: PreflightIn) -> dict[str, Any]:
    registered={host["ip"] for host in db.list_hosts()}
    ips=[ip for ip in dict.fromkeys(payload.ips) if ip in registered]
    if not ips:
        raise HTTPException(400, "등록된 대상 IP가 없습니다.")
    return security.preflight(ips)

@app.get("/api/jobs")
def get_jobs(limit: int=50) -> list[dict[str, Any]]:
    return jobs.list_jobs(max(1,min(limit,200)))

@app.get("/api/jobs/{job_id}/evidence")
def download_job_evidence(job_id: str) -> Response:
    if jobs.get_job(job_id) is None:
        raise HTTPException(404, "작업을 찾을 수 없습니다.")
    return Response(content=security.evidence_zip(job_id),media_type="application/zip",
      headers={"Content-Disposition":f'attachment; filename="SSAP-evidence-{job_id}.zip"',
               "Cache-Control":"no-store"})

@app.get("/api/jobs/{job_id}/evidence-summary")
def get_job_evidence_summary(job_id: str) -> dict[str,Any]:
    if jobs.get_job(job_id) is None:
        raise HTTPException(404,"작업을 찾을 수 없습니다.")
    try:return security.evidence_summary(job_id)
    except ValueError as exc:raise HTTPException(404,"생성된 증적이 없습니다.") from exc

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = jobs.get_job(job_id)
    if job is None:
        raise HTTPException(404, "작업을 찾을 수 없습니다.")
    return job
