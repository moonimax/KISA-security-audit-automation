# SSAP — KISA 보안점검 오케스트레이션

FastAPI 대시보드에서 UNIX, WEB, DBMS 점검·자동조치·승인조치를 실행하는 프로젝트다.
각 진단영역은 독립된 Ansible 프로젝트로 유지하고 `backend/`가 공통 API와 실행 흐름을 연결한다.

## 구조

```text
backend/                  FastAPI, DB 저장, 영역별 작업/인벤토리 연결
frontend/                 정적 대시보드
inventory/hosts.ini       전체 자산을 역할별로 묶은 통합 인벤토리
unix/                     U-01~U-67 Ansible 프로젝트
  check/ fix/ lib/
  inventory/ playbooks/ reports/ tools/
web/                      WEB-01~WEB-26 Ansible 프로젝트
  check/ fix/ lib/
  inventory/ playbooks/ reports/ tools/
db/                       MySQL D-항목 Ansible 프로젝트
  check/ fix/ lib/
  inventory/ playbooks/ reports/ tasks/ templates/ tools/
```

영역별 실행 경로와 플레이북 이름은 `backend/runtime.py` 한 곳에서 관리한다.
대시보드에서 호스트를 등록하거나 삭제하면 다음 인벤토리가 진단영역에 맞게 동기화된다.

- `inventory/hosts.ini` (통합 보기: 관리/UNIX/WEB/DBMS 그룹)
- `unix/inventory/hosts.ini`
- `web/inventory/hosts.ini`
- `db/inventory/hosts.ini`

## 실행 준비

Python 3.10 이상, Ansible, MySQL과 다음 패키지가 필요하다.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
```

`backend/.env`에 콘솔 DB 접속 정보를 설정한다. 파일이 없으면 코드의 개발 기본값을 사용한다.

```dotenv
KISA_MYSQL_HOST=127.0.0.1
KISA_MYSQL_PORT=3306
KISA_MYSQL_USER=kisa
KISA_MYSQL_PASSWORD=change-me
KISA_MYSQL_DB=kisa_console
```

DBMS의 `db/inventory/group_vars/all.yml`은 Ansible Vault 값이 있으므로 운영 환경에서는
`db/.vault_pass`를 별도로 준비한다. 이 파일과 `backend/.env`는 커밋하지 않는다.

## 콘솔 실행

프로젝트 루트에서 백엔드를 시작한다.

```bash
uvicorn backend.main:app --reload --port 8000
```

프론트엔드는 별도 터미널에서 정적 서버로 연다.

```bash
python3 -m http.server 8080 --directory frontend
```

## 엑셀 대시보드

운영 엑셀의 단일 생성 코드는 `ssap_reports.py`이다. 웹의 “최신 보안
대시보드 엑셀 다운로드” 버튼은 저장된 xlsx 파일을 선택하지 않고, 요청 시점의
DB 결과로 새 파일을 생성한다. 다운로드 파일명은
`ssap_reports_YYYYMMDD_HHMM.xlsx` 형식이다.

직접 실행하면 재현 가능한 샘플 데이터로 `ssap_reports_preview.xlsx`를 생성한다.
웹 다운로드는 같은 파일의 `build_report_bytes()`를 실행하되 현재 DB 결과를 사용한다.

```bash
python3 ssap_reports.py
```

최초 실행 시 관리자 계정이 없을 때만 `admin / P@ssw0rd`가 생성된다.
로그인 직후 비밀번호를 변경한다.

## 영역별 수동 실행
## 실습용 SSH Host CA

IP 등록 화면에서 관리자 재인증 후 **실습 Host CA 초기화**를 실행한다. CA 개인키는
Git 제외 경로인 `runtime/ssh_host_ca`에 권한 `0600`으로 저장되고, 공개키는
`runtime/ssh_host_ca.pub`에 저장된다. 이 구성은 실습 전용이며 운영 환경에서는
Vault 또는 HSM 기반 서명 서비스로 교체한다.

기존 서버는 먼저 콘솔 지문 방식으로 SSH 신원을 승인한 다음 **인증서 배포**를
실행한다. 배포 시 대상의 `/etc/ssh/sshd_config`를 타임스탬프 백업하고,
`sshd -t` 검사와 서비스 reload가 모두 성공한 경우에만 네트워크에서 CA 인증서를
재검증한다. CA 인증 호스트는 이후 개별 지문 승인 없이 인증서의 CA 서명과
호스트명/IP principal로 검증된다.



대시보드를 통하지 않을 때는 각 영역 디렉터리에서 실행한다.

```bash
cd unix
ansible-playbook playbooks/deploy.yml -e target_hosts=<host>
ansible-playbook playbooks/check.yml -e target_hosts=<host>
ansible-playbook playbooks/audit.yml -e target_hosts=<host>

cd ../web
ansible-playbook playbooks/deploy.yml -e target_hosts=<host>
ansible-playbook playbooks/check.yml -e target_hosts=<host>
ansible-playbook playbooks/audit.yml -e target_hosts=<host>

cd ../db
ansible-playbook playbooks/deploy.yml -e target_hosts=<host>
ansible-playbook playbooks/check.yml -e target_hosts=<host>
ansible-playbook playbooks/audit.yml -e target_hosts=<host>
ansible-playbook playbooks/remediate_approved.yml \
  -e target_hosts=<host> \
  -e mysql_security_selected_codes=D-08,D-10 \
  -e mysql_security_confirm=true
```

모든 영역의 승인조치는 `playbooks/remediate_approved.yml`을 사용한다.
콘솔 작업 러너는 각 영역에서 배포 후 점검·조치를 실행하고, 결과를 각 영역의
`reports/`에서 읽어 공통 DB에 저장한다.

## 안전 원칙

- 점검 플레이북은 설정을 변경하지 않는다.
- 자동조치는 점검 후 별도 플레이북으로 실행한다.
- 승인요청 항목은 선택 코드와 확인 플래그가 모두 있어야 실행한다.
- DBMS 승인조치에서는 자동조치 항목을 다시 실행하지 않는다.
- 배포 릴리스는 manifest 검증을 통과한 뒤에만 `current`로 전환한다.
