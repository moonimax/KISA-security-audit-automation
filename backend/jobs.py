"""사전점검 게이트, DB 영속 상태/잠금, 증적을 사용하는 Ansible 작업 러너."""
import json, subprocess, threading, time, uuid
from typing import Optional
from . import db, security
from .runtime import DomainRuntime, RUNTIMES, domain_for_code
PLAYBOOK_TIMEOUT_SECONDS=1800

class HostBusyError(RuntimeError):
    def __init__(self,ips):self.ips=ips;super().__init__("이미 다른 작업이 실행 중인 서버: "+", ".join(ips))

def _new_job(kind,targets,domains=None):
    job_id=uuid.uuid4().hex[:12];security.create_job(job_id,kind,targets,domains);return job_id
def _append_log(job_id,text):security.append_log(job_id,text)
def _finish(job_id,ok,error=None):security.update_job(job_id,status="success" if ok else "failed",error=error,finished_at=time.time())
def get_job(job_id):return security.get_job(job_id)
def list_jobs(limit=50):return security.list_jobs(limit)

def _run_guarded(job_id,function,hosts,*args):
    try:
        result=security.preflight([x[1] for x in hosts],exclude=job_id);security.update_job(job_id,preflight=result)
        for host in result["hosts"]:
            _append_log(job_id,f"[사전점검] {host['ip']} {'통과' if host['ok'] else '차단'}\n")
            for check in host["checks"]:_append_log(job_id,f"  - {check['name']}: {check.get('status','fail').upper()} ({check['detail']})\n")
        if not result["ok"]:_finish(job_id,False,"사전점검 실패로 원격 작업을 차단했습니다.");return
        function(job_id,hosts,*args)
    except Exception as exc:
        _append_log(job_id,f"[내부 오류] {type(exc).__name__}: {exc}\n");_finish(job_id,False,"작업 처리 중 내부 오류가 발생했습니다.")
    finally:
        try:security.build_evidence(job_id)
        except Exception as exc:_append_log(job_id,f"[증적 오류] {type(exc).__name__}: {exc}\n")
        security.release_locks(job_id)

def _run_playbook(job_id,runtime:DomainRuntime,playbook,extra_vars,target_hosts):
    cmd=["ansible-playbook","-i",str(runtime.inventory),playbook,"-e",f"target_hosts={target_hosts}"]
    for k,v in extra_vars.items():cmd += ["-e",f"{k}={v}"]
    _append_log(job_id,f"\n[{runtime.name}] $ {' '.join(cmd)}\n")
    try:p=subprocess.run(cmd,cwd=runtime.root,capture_output=True,text=True,timeout=PLAYBOOK_TIMEOUT_SECONDS,env=security.ansible_environment())
    except subprocess.TimeoutExpired as exc:_append_log(job_id,f"[시간초과] {exc}\n");return False
    except FileNotFoundError:_append_log(job_id,"[오류] ansible-playbook 실행 파일을 찾을 수 없습니다.\n");return False
    _append_log(job_id,p.stdout)
    if p.stderr:_append_log(job_id,p.stderr)
    return p.returncode==0

def _ingest_host_report(job_id,runtime,host,ip,suffix,run_kind="점검"):
    path=runtime.reports_dir/f"{host}{suffix}"
    if not path.exists():_append_log(job_id,f"[DB] {path.name} 파일이 없어 건너뜁니다.\n");return
    saved=db.save_results(host=host,results=json.loads(path.read_text()),ip=ip,run_kind=run_kind)
    _append_log(job_id,f"[DB] {host}: {path.name} → {saved}건 저장\n")

def _read_report(runtime,host,suffix):
    path=runtime.reports_dir/f"{host}{suffix}"
    if not path.exists():return []
    try:return json.loads(path.read_text())
    except (OSError,json.JSONDecodeError):return []

def _score(rows):
    weights={"상":10,"중":8,"하":6};maximum=deduction=0
    for row in rows:
        weight=weights.get(str(row.get("severity") or "").strip(),0);maximum+=weight
        status=str(row.get("status") or "").strip()
        if status in {"일부조치","PARTIAL","partial"}:deduction+=weight*.5
        elif status not in {"양호","O","o"}:deduction+=weight
    return round(((maximum-deduction)/maximum)*100,2) if maximum else None

def _automatic_updates(ip,before,after):
    after_by_code={str(row.get("code") or ""):row for row in after}
    updates=[]
    for row in before:
        before_status=str(row.get("status") or "결과 없음")
        if row.get("action_tag")!="자동조치" or not row.get("code") or before_status in {"양호","O","o"}:continue
        current=after_by_code.get(str(row["code"]));after_status=str((current or {}).get("status") or "결과 없음")
        if before_status in {"양호","O","o"} and after_status in {"양호","O","o"}:outcome="already_good"
        elif before_status not in {"양호","O","o"} and after_status in {"양호","O","o"}:outcome="fixed"
        elif current:outcome="unchanged"
        else:outcome="unknown"
        updates.append({"ip":ip,"code":str(row["code"]),"title":row.get("title") or "-",
          "before":before_status,"after":after_status,"outcome":outcome,
          "detail":(current or {}).get("detail") or "","source":"자동조치"})
    return updates

def _domain_targets(hosts,selected_domains):
    requested=set(RUNTIMES) if "ALL" in selected_domains else set(selected_domains)
    return {d:[(h,ip) for h,ip,domains in hosts if d in domains] for d in RUNTIMES if d in requested}

def _run_check_job(job_id,hosts,selected_domains):
    all_before=[];all_after=[];updates=[]
    for domain,pairs in _domain_targets(hosts,selected_domains).items():
        if not pairs:continue
        runtime=RUNTIMES[domain];targets=",".join(h for h,_ in pairs)
        if runtime.deploy_playbook and not _run_playbook(job_id,runtime,runtime.deploy_playbook,{},targets):_finish(job_id,False,f"{domain} 점검 파일 배포 실패");return
        if not _run_playbook(job_id,runtime,runtime.check_playbook,{},targets):_finish(job_id,False,f"{domain} 점검 실행 실패");return
        before_by_host={h:_read_report(runtime,h,runtime.check_report_suffix) for h,_ip in pairs}
        for h,ip in pairs:
            all_before.extend(before_by_host[h]);_ingest_host_report(job_id,runtime,h,ip,runtime.check_report_suffix,"점검")
        if not _run_playbook(job_id,runtime,runtime.audit_playbook,{},targets):_finish(job_id,False,f"{domain} 자동조치 실패");return
        for h,ip in pairs:
            after=_read_report(runtime,h,runtime.audit_report_suffix);all_after.extend(after)
            updates.extend(_automatic_updates(ip,before_by_host[h],after))
            after_by_code={str(row.get("code") or ""):row for row in after}
            all_after.extend(after_by_code.get(str(row.get("code") or ""),row) for row in before_by_host[h]
              if str(row.get("code") or "") not in after_by_code)
            _ingest_host_report(job_id,runtime,h,ip,runtime.audit_report_suffix,"자동조치")
            if domain=="DBMS":_ingest_host_report(job_id,runtime,h,ip,runtime.check_report_suffix,"자동조치 재점검")
    security.update_job(job_id,result={"remediation_updates":updates,"initial_score":_score(all_before),
      "final_score":_score(all_after),"source":"자동조치"})
    _finish(job_id,True)


def _run_check_only_job(job_id,hosts,selected_domains):
    for domain,pairs in _domain_targets(hosts,selected_domains).items():
        if not pairs:continue
        runtime=RUNTIMES[domain];targets=",".join(h for h,_ in pairs)
        if runtime.deploy_playbook and not _run_playbook(job_id,runtime,runtime.deploy_playbook,{},targets):
            _finish(job_id,False,f"{domain} 점검 파일 배포 실패");return
        if not _run_playbook(job_id,runtime,runtime.check_playbook,{},targets):
            _finish(job_id,False,f"{domain} 점검 실행 실패");return
        for h,ip in pairs:_ingest_host_report(job_id,runtime,h,ip,runtime.check_report_suffix,"점검만")
    _finish(job_id,True)

def _start(kind,hosts,function,*args,domains=None):
    job_id=_new_job(kind,[h for h,_ip,_data in hosts],domains)
    conflicts=security.acquire_locks(job_id,kind,[ip for _h,ip,_data in hosts])
    if conflicts:_finish(job_id,False,"다른 작업 실행 중");raise HostBusyError(conflicts)
    threading.Thread(target=_run_guarded,args=(job_id,function,hosts,*args),daemon=True).start();return job_id

def start_check_job(hosts,domains=None):
    selected=domains or ["ALL"];job_id=_start("check",hosts,_run_check_job,selected,domains=selected)
    _append_log(job_id,f"[진단영역] {', '.join(selected)} · 대상 {len(hosts)}대\n");return job_id

def start_check_only_job(hosts,domains=None):
    selected=domains or ["ALL"];job_id=_start("check-only",hosts,_run_check_only_job,selected,domains=selected)
    _append_log(job_id,f"[점검만] {', '.join(selected)} · 대상 {len(hosts)}대\n");return job_id

def _run_remediate_job(job_id,items):
    grouped={}
    for host,ip,codes in items:
        for code in codes:grouped.setdefault((domain_for_code(code),host,ip),[]).append(code)
    for (domain,host,ip),codes in grouped.items():
        runtime=RUNTIMES[domain]
        if runtime.deploy_playbook and not _run_playbook(job_id,runtime,runtime.deploy_playbook,{},host):_finish(job_id,False,f"{host} 배포 실패");return
        extra={"mysql_security_selected_codes":",".join(codes),"mysql_security_confirm":"true"} if domain=="DBMS" else {"kisa_selected_codes":",".join(codes),"kisa_confirm":"true"}
        if not _run_playbook(job_id,runtime,runtime.remediate_playbook,extra,host):_finish(job_id,False,f"{host} 승인조치 실패");return
        if domain!="DBMS" and not _run_playbook(job_id,runtime,runtime.check_playbook,{},host):_finish(job_id,False,f"{host} 재점검 실패");return
        _ingest_host_report(job_id,runtime,host,ip,runtime.check_report_suffix,"승인조치 재점검")
    _finish(job_id,True)

def start_remediate_job(items):return _start("remediate",items,_run_remediate_job)
