"""SSH 신원 검증, 사전점검, SQLite 작업 상태/잠금, SHA-256 증적."""
import base64, hashlib, io, json, os, re, secrets, shutil, sqlite3, subprocess, tempfile, time, zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional
from .runtime import PROJECT_ROOT, RUNTIMES

RUNTIME=PROJECT_ROOT/"runtime"; DB=RUNTIME/"security_state.db"
KNOWN_HOSTS=RUNTIME/"ssh_known_hosts"; EVIDENCE=PROJECT_ROOT/"evidence"
SUPPORTED_OS={"rocky","rhel","centos","almalinux","ubuntu","debian"}

def _db():
    RUNTIME.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(DB,timeout=10);conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL");return conn

def init():
    with _db() as c:c.executescript("""
    CREATE TABLE IF NOT EXISTS identities(ip TEXT PRIMARY KEY,port INTEGER,approved_type TEXT,
      approved_key TEXT,approved_fp TEXT,observed_type TEXT,observed_key TEXT,observed_fp TEXT,
      status TEXT,scanned_at REAL,approved_at REAL);
    CREATE TABLE IF NOT EXISTS statuses(ip TEXT PRIMARY KEY,status TEXT,detail TEXT,latency_ms INTEGER,
      preflight TEXT,checked_at REAL);
    CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT,targets TEXT,domains TEXT,status TEXT,
      log TEXT,error TEXT,preflight TEXT,evidence_path TEXT,created_at REAL,finished_at REAL,heartbeat_at REAL);
    CREATE TABLE IF NOT EXISTS host_certificates(ip TEXT PRIMARY KEY,certificate_type TEXT,
      certificate_key TEXT,certificate_fp TEXT,principals TEXT,status TEXT,
      issued_at REAL,deployed_at REAL);
    CREATE TABLE IF NOT EXISTS locks(ip TEXT PRIMARY KEY,job_id TEXT,kind TEXT,locked_at REAL,heartbeat_at REAL);
    CREATE TABLE IF NOT EXISTS identity_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT,action TEXT,
      approver TEXT,observed_fp TEXT,trusted_fp TEXT,previous_fp TEXT,result TEXT,created_at REAL);
    CREATE TABLE IF NOT EXISTS api_sessions(token_hash TEXT PRIMARY KEY,login_id TEXT,created_at REAL,expires_at REAL);
    """)
    with _db() as c:
        columns={row["name"] for row in c.execute("PRAGMA table_info(jobs)").fetchall()}
        if "result" not in columns:c.execute("ALTER TABLE jobs ADD COLUMN result TEXT")

def identity(ip):
    init()
    with _db() as c:
        r=c.execute("SELECT * FROM identities WHERE ip=?",(ip,)).fetchone()
        cert=c.execute("SELECT status,certificate_fp,principals FROM host_certificates WHERE ip=?",(ip,)).fetchone()
    if not r:return {"status":"unverified","certificate_status":cert["status"] if cert else "none"}
    item={k:r[k] for k in ("ip","port","status","approved_fp","observed_fp","observed_type","scanned_at","approved_at")}
    item["certificate_status"]=cert["status"] if cert else "none"
    if cert:item["certificate_fp"]=cert["certificate_fp"]
    return item

def _ca_private_path():return RUNTIME/"ssh_host_ca"
def _ca_public_path():return RUNTIME/"ssh_host_ca.pub"

def ca_status():
    private=_ca_private_path();public=_ca_public_path()
    if not private.exists() and not public.exists():return {"ready":False,"mode":"lab-local"}
    if not private.exists() or not public.exists():
        return {"ready":False,"mode":"lab-local","error":"SSH Host CA 파일이 불완전합니다."}
    parts=public.read_text(encoding="utf-8").split()
    if len(parts)<2:return {"ready":False,"mode":"lab-local","error":"SSH Host CA 공개키 형식이 올바르지 않습니다."}
    return {"ready":True,"mode":"lab-local","fingerprint":fingerprint(parts[1]),
      "key_type":parts[0],"private_key_mode":oct(private.stat().st_mode & 0o777)}

def initialize_host_ca():
    status=ca_status()
    if status.get("ready"):return status
    if status.get("error"):raise RuntimeError(status["error"])
    RUNTIME.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(dir=RUNTIME,prefix=".ssh-host-ca."));temp_private=work/"ca"
    try:
        proc=subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-C",
          "SSAP lab SSH Host CA","-f",str(temp_private)],capture_output=True,text=True,timeout=15)
        if proc.returncode!=0:raise RuntimeError((proc.stderr or "SSH Host CA 생성 실패").strip())
        os.chmod(temp_private,0o600);os.chmod(Path(str(temp_private)+".pub"),0o644)
        os.replace(temp_private,_ca_private_path());os.replace(Path(str(temp_private)+".pub"),_ca_public_path())
    finally:shutil.rmtree(work,ignore_errors=True)
    rebuild_known_hosts();return ca_status()

def _certificate_details(certificate_type,key,hostname,ip):
    public=_ca_public_path()
    if not public.exists():raise ValueError("SSH Host CA가 초기화되지 않았습니다.")
    ca_parts=public.read_text(encoding="utf-8").split();ca_fp=fingerprint(ca_parts[1])
    fd,name=tempfile.mkstemp(dir=RUNTIME,prefix=".host-cert.")
    try:
        with os.fdopen(fd,"w") as stream:stream.write(f"{certificate_type} {key}\n")
        proc=subprocess.run(["ssh-keygen","-L","-f",name],capture_output=True,text=True,timeout=10)
        if proc.returncode!=0:raise ValueError("SSH 호스트 인증서를 해석할 수 없습니다.")
        output=proc.stdout
    finally:
        if os.path.exists(name):os.unlink(name)
    if ca_fp not in output:raise ValueError("신뢰하는 SSH Host CA가 서명한 인증서가 아닙니다.")
    match=re.search(r"Principals:\s*\n(.*?)\n\s*Critical Options:",output,re.S)
    principals=[line.strip() for line in (match.group(1).splitlines() if match else []) if line.strip() and line.strip()!="(none)"]
    if ip not in principals:raise ValueError("SSH 호스트 인증서 principal에 대상 IP가 없습니다.")
    if hostname and hostname not in principals:raise ValueError("SSH 호스트 인증서 principal에 대상 호스트명이 없습니다.")
    return {"fingerprint":fingerprint(key),"principals":principals,"details":output}

def _scan_host_certificate(ip,port=22):
    from . import db
    host=next((item for item in db.list_hosts() if item["ip"]==ip),None)
    if not host or not ca_status().get("ready"):return None
    try:proc=subprocess.run(["ssh-keyscan","-c","-T","7","-p",str(port),"-t","ed25519,rsa",ip],
      capture_output=True,text=True,timeout=9)
    except (FileNotFoundError,subprocess.TimeoutExpired):return None
    for line in proc.stdout.splitlines():
        parts=line.split()
        if line.startswith("#") or len(parts)<2:continue
        certificate_type,certificate_key=(parts[0],parts[1]) if parts[0].startswith("ssh-") else ((parts[1],parts[2]) if len(parts)>=3 else ("",""))
        if "-cert-v01@openssh.com" not in certificate_type:continue
        try:details=_certificate_details(certificate_type,certificate_key,host["hostname"],ip)
        except ValueError:continue
        now=time.time();principals=json.dumps(details["principals"],ensure_ascii=False)
        with _db() as c:
            c.execute("""INSERT INTO identities(ip,port,approved_type,approved_key,approved_fp,
              observed_type,observed_key,observed_fp,status,scanned_at,approved_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET port=excluded.port,
              approved_type=excluded.approved_type,approved_key=excluded.approved_key,
              approved_fp=excluded.approved_fp,observed_type=excluded.observed_type,
              observed_key=excluded.observed_key,observed_fp=excluded.observed_fp,
              status=excluded.status,scanned_at=excluded.scanned_at,approved_at=excluded.approved_at""",
              (ip,port,certificate_type,certificate_key,details["fingerprint"],certificate_type,certificate_key,details["fingerprint"],"certified",now,now))
            c.execute("""INSERT INTO host_certificates(ip,certificate_type,certificate_key,certificate_fp,
              principals,status,issued_at,deployed_at) VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(ip) DO UPDATE SET certificate_type=excluded.certificate_type,
              certificate_key=excluded.certificate_key,certificate_fp=excluded.certificate_fp,
              principals=excluded.principals,status=excluded.status,deployed_at=excluded.deployed_at""",
              (ip,certificate_type,certificate_key,details["fingerprint"],principals,"valid",now,now))
        rebuild_known_hosts();return identity(ip)
    return None

def public_identity(ip):
    """Return SSH identity state without disclosing an unapproved observed key."""
    item=identity(ip)
    item.pop("observed_fp",None)
    if item.get("status") not in {"trusted","certified"}:item.pop("approved_fp",None)
    return item

def fingerprint(key):
    raw=base64.b64decode(key,validate=True)
    return "SHA256:"+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")

def _registered(ip):
    from . import db
    return any(h["ip"]==ip for h in db.list_hosts())

def scan(ip,port=22):
    if not _registered(ip):raise ValueError("등록되지 않은 서버입니다.")
    certificate=_scan_host_certificate(ip,port)
    if certificate:return certificate
    try:p=subprocess.run(["ssh-keyscan","-T","7","-p",str(port),"-t","ed25519,rsa",ip],
      capture_output=True,text=True,timeout=9)
    except (FileNotFoundError,subprocess.TimeoutExpired) as e:raise RuntimeError("SSH 호스트 키 조회 실패") from e
    keys=[]
    for line in p.stdout.splitlines():
        x=line.split()
        if len(x)>=3 and not line.startswith("#") and x[1].startswith("ssh-"):keys.append((x[1],x[2]))
    if not keys:raise RuntimeError("SSH 서버에서 호스트 키를 받지 못했습니다.")
    kind,key=next((x for x in keys if x[0]=="ssh-ed25519"),keys[0]);fp=fingerprint(key);now=time.time()
    with _db() as c:
        old=c.execute("SELECT approved_fp FROM identities WHERE ip=?",(ip,)).fetchone()
        approved=old["approved_fp"] if old else None
        state="pending" if not approved else ("trusted" if approved==fp else "changed")
        c.execute("""INSERT INTO identities(ip,port,observed_type,observed_key,observed_fp,status,scanned_at)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET port=excluded.port,
          observed_type=excluded.observed_type,observed_key=excluded.observed_key,
          observed_fp=excluded.observed_fp,status=excluded.status,scanned_at=excluded.scanned_at""",
          (ip,port,kind,key,fp,state,now))
    return identity(ip)

def _normalize_fingerprint(value):
    match=re.search(r"SHA256:[A-Za-z0-9+/]+={0,2}",str(value or "").strip())
    return match.group(0).rstrip("=") if match else ""

def record_identity_audit(ip,action,approver,observed_fp="",trusted_fp="",previous_fp="",result=""):
    init()
    with _db() as c:c.execute("""INSERT INTO identity_audit
      (ip,action,approver,observed_fp,trusted_fp,previous_fp,result,created_at)
      VALUES(?,?,?,?,?,?,?,?)""",(ip,action,approver,observed_fp,trusted_fp,previous_fp,result,time.time()))

def identity_audit(ip,limit=20):
    init()
    with _db() as c:rows=c.execute(
      "SELECT * FROM identity_audit WHERE ip=? ORDER BY created_at DESC,id DESC LIMIT ?",(ip,limit)).fetchall()
    return [{k:r[k] for k in ("id","ip","action","approver","observed_fp","trusted_fp","previous_fp","result","created_at")} for r in rows]

def approve(ip,trusted_fingerprint,approver):
    trusted=_normalize_fingerprint(trusted_fingerprint)
    with _db() as c:
        row=c.execute("SELECT * FROM identities WHERE ip=?",(ip,)).fetchone()
        current=_normalize_fingerprint(row["observed_fp"]) if row else ""
        previous=_normalize_fingerprint(row["approved_fp"]) if row else ""
        if not row or not current:
            record_identity_audit(ip,"approve",approver,current,trusted,previous,"observed_changed")
            raise ValueError("조회된 SSH 호스트 키 지문이 변경되었습니다. 다시 조회하세요.")
        if not trusted or trusted!=current:
            record_identity_audit(ip,"approve",approver,current,trusted,previous,"fingerprint_mismatch")
            raise ValueError("직접 확인한 SSH 호스트 키 지문과 네트워크 조회 지문이 일치하지 않습니다.")
        c.execute("""UPDATE identities SET approved_type=observed_type,approved_key=observed_key,
          approved_fp=observed_fp,status='trusted',approved_at=? WHERE ip=?""",(time.time(),ip))
    record_identity_audit(ip,"approve",approver,current,trusted,previous,"approved")
    rebuild_known_hosts();return identity(ip)
def _issue_host_certificate(ip,hostname,key_type,key):
    status=ca_status()
    if not status.get("ready"):raise ValueError("먼저 실습용 SSH Host CA를 초기화하세요.")
    if key_type not in {"ssh-ed25519","ssh-rsa"}:raise ValueError("지원하지 않는 SSH 호스트 키 형식입니다.")
    work=Path(tempfile.mkdtemp(dir=RUNTIME,prefix=".host-certificate."))
    public=work/"host_key.pub"
    try:
        public.write_text(f"{key_type} {key}\n",encoding="utf-8")
        serial=int(time.time()*1000)
        proc=subprocess.run(["ssh-keygen","-q","-s",str(_ca_private_path()),"-I",
          f"ssap:{hostname}:{ip}:{serial}","-h","-n",f"{hostname},{ip}",
          "-V","-5m:+52w","-z",str(serial),str(public)],capture_output=True,text=True,timeout=15)
        if proc.returncode!=0:raise RuntimeError((proc.stderr or "SSH 호스트 인증서 발급 실패").strip())
        certificate=work/"host_key-cert.pub"
        if not certificate.exists():raise RuntimeError("발급된 SSH 호스트 인증서 파일을 찾지 못했습니다.")
        return certificate.read_text(encoding="utf-8")
    finally:shutil.rmtree(work,ignore_errors=True)

def deploy_host_certificate(ip,approver):
    from . import db
    host=next((item for item in db.list_hosts() if item["ip"]==ip),None)
    if not host:raise ValueError("등록되지 않은 서버입니다.")
    current=identity(ip)
    if current.get("status")=="certified":return public_identity(ip)
    if current.get("status") not in {"trusted","pending","unverified"}:
        raise ValueError("SSH 호스트 키가 변경된 서버는 자동 등록할 수 없습니다.")
    if current.get("status") in {"pending","unverified"}:
        current=scan(ip,current.get("port") or 22)
        if current.get("status")=="certified":
            record_identity_audit(ip,"cert_deploy",approver,current.get("approved_fp") or "","","","already_certified")
            return public_identity(ip)
        if current.get("status")!="pending":
            raise ValueError("SSH 호스트 키 상태를 확인할 수 없습니다.")
        with _db() as c:
            c.execute("""UPDATE identities SET approved_type=observed_type,
              approved_key=observed_key,approved_fp=observed_fp,status='trusted',
              approved_at=? WHERE ip=?""",(time.time(),ip))
        record_identity_audit(ip,"bootstrap",approver,current.get("observed_fp") or "","","","auto_trusted_lab")
        current=identity(ip)
    with _db() as c:row=c.execute("SELECT * FROM identities WHERE ip=?",(ip,)).fetchone()
    key_type=row["approved_type"];key=row["approved_key"]
    certificate=_issue_host_certificate(ip,host["hostname"],key_type,key)
    certificate_path="/etc/ssh/ssh_host_ed25519_key-cert.pub" if key_type=="ssh-ed25519" else "/etc/ssh/ssh_host_rsa_key-cert.pub"
    encoded=base64.b64encode(certificate.encode()).decode()
    script=f"""set -eu
config=/etc/ssh/sshd_config
certificate={certificate_path}
backup=/etc/ssh/sshd_config.ssap-backup-$(date +%Y%m%d%H%M%S)
sudo cp -a "$config" "$backup"
printf '%s' '{encoded}' | base64 -d | sudo tee "$certificate" >/dev/null
sudo chmod 0644 "$certificate"
if ! sudo grep -Fqx 'HostCertificate {certificate_path}' "$config"; then
  printf '\n# SSAP lab SSH Host CA\nHostCertificate {certificate_path}\n' | sudo tee -a "$config" >/dev/null
fi
if ! sudo sshd -t; then
  sudo cp -a "$backup" "$config"
  sudo rm -f "$certificate"
  exit 20
fi
if ! (sudo systemctl reload sshd || sudo systemctl reload ssh); then
  sudo cp -a "$backup" "$config"
  sudo rm -f "$certificate"
  sudo sshd -t
  sudo systemctl reload sshd || sudo systemctl reload ssh
  exit 21
fi
"""
    proc=_ssh(ip,"sh -s",input_text=script)
    if proc.returncode!=0:
        record_identity_audit(ip,"cert_deploy",approver,current.get("approved_fp") or "","","","deploy_failed")
        raise RuntimeError((proc.stderr or proc.stdout or "SSH 호스트 인증서 배포 실패")[-800:])
    verified=None
    for _ in range(3):
        time.sleep(0.4);verified=_scan_host_certificate(ip,current.get("port") or 22)
        if verified:break
    if not verified:
        record_identity_audit(ip,"cert_deploy",approver,current.get("approved_fp") or "","","","verify_failed")
        raise RuntimeError("인증서를 배포했지만 네트워크에서 CA 인증서를 검증하지 못했습니다.")
    record_identity_audit(ip,"cert_deploy",approver,verified.get("approved_fp") or "","","","certificate_approved")
    return public_identity(ip)



def create_session(login_id,ttl_seconds=28800):
    init();token=secrets.token_urlsafe(32);digest=hashlib.sha256(token.encode()).hexdigest();now=time.time()
    with _db() as c:
        c.execute("DELETE FROM api_sessions WHERE expires_at<?",(now,))
        c.execute("INSERT INTO api_sessions VALUES(?,?,?,?)",(digest,login_id,now,now+ttl_seconds))
    return token

def session_user(token):
    if not token:return None
    digest=hashlib.sha256(token.encode()).hexdigest();now=time.time()
    with _db() as c:
        row=c.execute("SELECT login_id FROM api_sessions WHERE token_hash=? AND expires_at>?",(digest,now)).fetchone()
    return row["login_id"] if row else None

def revoke_session(token):
    if not token:return
    digest=hashlib.sha256(token.encode()).hexdigest()
    with _db() as c:c.execute("DELETE FROM api_sessions WHERE token_hash=?",(digest,))

def remove_host(ip):
    with _db() as c:
        c.execute("DELETE FROM identities WHERE ip=?",(ip,));c.execute("DELETE FROM statuses WHERE ip=?",(ip,))
        c.execute("DELETE FROM host_certificates WHERE ip=?",(ip,))

def rebuild_known_hosts():
    init()
    with _db() as c:rows=c.execute("SELECT * FROM identities WHERE approved_fp IS NOT NULL").fetchall()
    lines=[];ca=ca_status()
    if ca.get("ready"):
        parts=_ca_public_path().read_text(encoding="utf-8").split()
        lines.append(f"@cert-authority * {parts[0]} {parts[1]}")
    for r in rows:
        if r["status"]=="certified":continue
        host=r["ip"] if r["port"]==22 else f"[{r['ip']}]:{r['port']}"
        lines.append(f"{host} {r['approved_type']} {r['approved_key']}")
    fd,tmp=tempfile.mkstemp(dir=RUNTIME,prefix=".known_hosts.")
    try:
        with os.fdopen(fd,"w") as f:f.write("\n".join(lines)+("\n" if lines else ""));f.flush();os.fsync(f.fileno())
        os.chmod(tmp,0o600);os.replace(tmp,KNOWN_HOSTS)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return KNOWN_HOSTS

def _user(ip):
    hr=re.compile(rf"\bansible_host={re.escape(ip)}(?:\s|$)");ur=re.compile(r"\bansible_user=(\S+)")
    for runtime in RUNTIMES.values():
        if runtime.inventory.exists():
            for line in runtime.inventory.read_text().splitlines():
                if hr.search(line):
                    m=ur.search(line)
                    if m:return m.group(1)
    return None

def _ssh(ip,remote,input_text=None):
    i=identity(ip);user=_user(ip)
    if i.get("status") not in {"trusted","certified"} or not user:raise RuntimeError("승인된 SSH 신원 또는 접속 계정이 없습니다.")
    rebuild_known_hosts()
    cmd=["ssh","-F","/dev/null","-o","BatchMode=yes","-o","ConnectTimeout=7",
      "-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={KNOWN_HOSTS}",
      "-p",str(i.get("port") or 22),f"{user}@{ip}",remote]
    return subprocess.run(cmd,input=input_text,capture_output=True,text=True,timeout=20)

def _save_status(ip,state,detail,latency=None,preflight=None):
    now=time.time();raw=json.dumps(preflight,ensure_ascii=False) if preflight else None
    with _db() as c:c.execute("""INSERT INTO statuses VALUES(?,?,?,?,?,?)
      ON CONFLICT(ip) DO UPDATE SET status=excluded.status,detail=excluded.detail,
      latency_ms=excluded.latency_ms,preflight=excluded.preflight,checked_at=excluded.checked_at""",
      (ip,state,detail,latency,raw,now))
    return {"status":state,"detail":detail,"latency_ms":latency,"preflight":preflight,"checked_at":now}

def status(ip):
    init()
    with _db() as c:r=c.execute("SELECT * FROM statuses WHERE ip=?",(ip,)).fetchone()
    if not r:return {"status":"unknown"}
    return {"status":r["status"],"detail":r["detail"],"latency_ms":r["latency_ms"],
      "preflight":json.loads(r["preflight"]) if r["preflight"] else None,"checked_at":r["checked_at"]}

def connection_check(ip):
    start=time.monotonic();i=identity(ip)
    if i.get("status") not in {"trusted","certified"}:return _save_status(ip,"blocked","SSH 서버 키 미승인 또는 변경")
    try:
        if scan(ip,i.get("port") or 22).get("status") not in {"trusted","certified"}:return _save_status(ip,"blocked","서버 키 불일치")
        p=_ssh(ip,"true");ms=round((time.monotonic()-start)*1000)
        if p.returncode==0:return _save_status(ip,"connected","SSH 신원 및 인증 확인 완료",ms)
        return _save_status(ip,"unreachable",(p.stderr or "SSH 인증 실패")[-500:],ms)
    except Exception as e:return _save_status(ip,"unreachable",str(e)[:500])

def locked_ips(exclude=None):
    init();sql="SELECT ip FROM locks"+(" WHERE job_id<>?" if exclude else "")
    with _db() as c:rows=c.execute(sql,(exclude,) if exclude else ()).fetchall()
    return {r["ip"] for r in rows}

def _check(name,ok,detail,summary="",commands=None,skipped=False):
    result={"name":name,"ok":bool(ok),"status":"skip" if skipped else ("ok" if ok else "fail"),"detail":detail}
    if summary or commands:
        result["fix"]={"summary":summary,"commands":commands or []}
    return result

def preflight_host(ip,exclude=None):
    item=identity(ip);user=_user(ip) or "<ssh-user>";key_ok=item.get("status") in {"trusted","certified"}
    if key_ok:
        try:key_ok=scan(ip,item.get("port") or 22).get("status") in {"trusted","certified"}
        except Exception:key_ok=False
    key_commands=[
      f"# 대상 서버 {ip}의 콘솔 또는 기존에 신뢰하는 Tailscale SSH에서 실행",
      "sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256",
    ]
    checks=[_check("ssh_identity",key_ok,"승인 키 일치" if key_ok else "미승인/키 변경",
      "대상 서버 콘솔에서 확인한 지문을 대시보드에 입력해 서버 측 비교를 통과한 뒤 승인하세요.",key_commands if not key_ok else [])]
    auth=os_ok=sudo=False;os_id="";transport_error=""
    if key_ok:
        try:
            proc=_ssh(ip,"sh -c 'cat /etc/os-release; printf \"\\n__SSAP_SUDO__\\n\"; sudo -n /usr/bin/true'")
            auth=proc.returncode in (0,1)
            match=re.search(r"^ID=[\"']?([^\"'\n]+)",proc.stdout,re.M)
            os_id=match.group(1).lower() if match else "";os_ok=os_id in SUPPORTED_OS;sudo=proc.returncode==0
            if not auth:transport_error=(proc.stderr or "SSH 인증 실패").strip()[-300:]
        except Exception as exc:transport_error=str(exc)
    if not key_ok:
        checks += [
          _check("ssh_auth",False,"SSH 신원 확인 후 검사","SSH 신원을 먼저 승인하세요.",skipped=True),
          _check("os_support",False,"SSH 신원 확인 후 검사","SSH 신원을 먼저 승인하세요.",skipped=True),
          _check("sudo_nopasswd",False,"SSH 신원 확인 후 검사","SSH 신원을 먼저 승인하세요.",skipped=True),
        ]
    else:
        auth_commands=[f"ssh -vv -o BatchMode=yes {user}@{ip} true"]
        checks.append(_check("ssh_auth",auth,"SSH 인증 성공" if auth else (transport_error or "SSH 인증 실패"),
          "SSH 계정과 공개키 인증 설정을 확인하세요.",auth_commands if not auth else []))
        if not auth:
            checks += [
              _check("os_support",False,"SSH 인증 성공 후 검사","SSH 인증을 먼저 해결하세요.",skipped=True),
              _check("sudo_nopasswd",False,"SSH 인증 성공 후 검사","SSH 인증을 먼저 해결하세요.",skipped=True),
            ]
        else:
            os_commands=[f"ssh {user}@{ip} 'cat /etc/os-release'"]
            sudo_commands=[f"ssh -t {user}@{ip} 'sudo -l'",f"ssh {user}@{ip} 'sudo -n /usr/bin/true'"]
            checks += [
              _check("os_support",os_ok,os_id or "OS 식별 실패",
                "지원 OS( Rocky/RHEL/Ubuntu/Debian 계열)인지 확인하세요.",os_commands if not os_ok else []),
              _check("sudo_nopasswd",sudo,"sudo -n 가능" if sudo else "비대화형 sudo 불가",
                "sudo -l로 권한을 확인하고 담당자가 승인한 sudoers 정책을 적용하세요.",sudo_commands if not sudo else []),
            ]
    conflict=ip in locked_ips(exclude)
    checks.append(_check("job_conflict",not conflict,"충돌 없음" if not conflict else "다른 작업 실행 중",
      "현재 작업이 끝난 뒤 다시 실행하세요." if conflict else ""))
    result={"ip":ip,"ok":all(x["ok"] for x in checks if x["status"]!="skip"),"checks":checks}
    _save_status(ip,"ready" if result["ok"] else "blocked","사전점검 통과" if result["ok"] else "사전점검 실패",preflight=result)
    return result

def preflight(ips,exclude=None):
    unique=list(dict.fromkeys(ips))
    with ThreadPoolExecutor(max_workers=min(4,max(1,len(unique)))) as p:hosts=list(p.map(lambda ip:preflight_host(ip,exclude),unique))
    return {"ok":all(h["ok"] for h in hosts),"hosts":hosts}

def ansible_environment():
    rebuild_known_hosts();env=os.environ.copy();env["ANSIBLE_HOST_KEY_CHECKING"]="True"
    env["ANSIBLE_SSH_ARGS"]=f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={KNOWN_HOSTS}";return env

def create_job(job_id,kind,targets,domains=None):
    init();now=time.time()
    with _db() as c:c.execute("""INSERT INTO jobs
      (id,kind,targets,domains,status,log,error,preflight,evidence_path,created_at,finished_at,heartbeat_at,result)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
      (job_id,kind,json.dumps(targets),json.dumps(domains or []),"running","",None,None,None,now,None,now,None))

def update_job(job_id,**values):
    fields=[];params=[]
    for k,v in values.items():
        if k in {"status","error","evidence_path","finished_at","preflight","result"}:
            fields.append(f"{k}=?");params.append(json.dumps(v,ensure_ascii=False) if k in {"preflight","result"} and v is not None else v)
    fields.append("heartbeat_at=?");params.extend((time.time(),job_id))
    with _db() as c:c.execute(f"UPDATE jobs SET {','.join(fields)} WHERE id=?",params)

def append_log(job_id,text):
    with _db() as c:c.execute("UPDATE jobs SET log=log||?,heartbeat_at=? WHERE id=?",(text,time.time(),job_id))

def _job(r):
    if not r:return None
    return {"id":r["id"],"kind":r["kind"],"targets":json.loads(r["targets"]),"domains":json.loads(r["domains"]),
      "status":r["status"],"log":r["log"],"error":r["error"],"preflight":json.loads(r["preflight"]) if r["preflight"] else None,
      "result":json.loads(r["result"]) if r["result"] else None,"evidence_available":bool(r["evidence_path"]),
      "created_at":r["created_at"],"finished_at":r["finished_at"]}

def get_job(job_id):
    init()
    with _db() as c:return _job(c.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone())

def list_jobs(limit=50):
    init()
    with _db() as c:return [_job(r) for r in c.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall()]

def acquire_locks(job_id,kind,ips):
    unique=list(dict.fromkeys(ips));now=time.time()
    with _db() as c:
        c.execute("BEGIN IMMEDIATE");c.execute("DELETE FROM locks WHERE heartbeat_at<?",(now-2100,))
        rows=c.execute("SELECT ip FROM locks WHERE ip IN (%s)"%",".join("?" for _ in unique),unique).fetchall()
        if rows:c.rollback();return [r["ip"] for r in rows]
        c.executemany("INSERT INTO locks VALUES(?,?,?,?,?)",[(ip,job_id,kind,now,now) for ip in unique]);c.commit()
    return []

def release_locks(job_id):
    with _db() as c:c.execute("DELETE FROM locks WHERE job_id=?",(job_id,))

SECRET=re.compile(r"(?i)(password|passwd|token|secret)(\s*[=:]\s*)(\S+)")
def build_evidence(job_id):
    job=get_job(job_id)
    if not job:raise ValueError("작업 없음")
    d=EVIDENCE/job_id;d.mkdir(parents=True,exist_ok=True)
    meta={k:v for k,v in job.items() if k!="log"};meta["collected_at"]=time.time()
    (d/"metadata.json").write_text(json.dumps(meta,ensure_ascii=False,indent=2,sort_keys=True))
    (d/"execution.log").write_text(SECRET.sub(r"\1\2[REDACTED]",job["log"]))
    for domain,runtime in RUNTIMES.items():
        if runtime.reports_dir.exists():
            for source in runtime.reports_dir.glob("*.json"):
                if any(source.name.startswith(h) for h in job["targets"]):
                    dest=d/"reports"/domain/source.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
    entries=[f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(d).as_posix()}" for p in sorted(d.rglob("*")) if p.is_file() and p.name!="manifest.sha256"]
    (d/"manifest.sha256").write_text("\n".join(entries)+"\n");update_job(job_id,evidence_path=str(d));return d

def evidence_zip(job_id):
    d=EVIDENCE/job_id
    if not d.is_dir():d=build_evidence(job_id)
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:
        for p in sorted(d.rglob("*")):
            if p.is_file():z.write(p,f"SSAP-evidence-{job_id}/{p.relative_to(d).as_posix()}")
    return out.getvalue()

def evidence_summary(job_id):
    d=EVIDENCE/job_id
    if not d.is_dir():raise ValueError("증적 없음")
    metadata_path=d/"metadata.json";manifest_path=d/"manifest.sha256";log_path=d/"execution.log"
    metadata=json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
    files=[];integrity_ok=True
    if manifest_path.is_file():
        for line in manifest_path.read_text().splitlines():
            if "  " not in line:continue
            expected,relative=line.split("  ",1);path=d/relative
            actual=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
            verified=bool(actual) and secrets.compare_digest(expected,actual)
            integrity_ok=integrity_ok and verified
            files.append({"path":relative,"sha256":expected,"verified":verified,"size":path.stat().st_size if path.is_file() else 0})
    else:integrity_ok=False
    log_lines=log_path.read_text(errors="replace").splitlines() if log_path.is_file() else []
    meaningful=[line for line in log_lines if line.strip()]
    preflight=metadata.get("preflight") or {}
    checks=[check for host in preflight.get("hosts",[]) for check in host.get("checks",[])]
    return {"job_id":job_id,"kind":metadata.get("kind"),"status":metadata.get("status"),
      "targets":metadata.get("targets") or [],"domains":metadata.get("domains") or [],
      "created_at":metadata.get("created_at"),"finished_at":metadata.get("finished_at"),
      "collected_at":metadata.get("collected_at"),"integrity_ok":integrity_ok,
      "file_count":len(files),"files":files,
      "preflight":{"ok":preflight.get("ok"),"passed":sum(bool(x.get("ok")) for x in checks),"total":len(checks)},
      "result":metadata.get("result"),"log_tail":meaningful[-12:]}
