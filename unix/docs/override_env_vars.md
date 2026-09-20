# 항목별 조치 오버라이드 환경변수

`fix/*.sh`는 `KISA_APPROVAL=true`만으로 조치가 실행되는 항목이 대부분이지만, 아래 12개 항목은 관리자가 값을 지정하지 않으면 **락아웃/서비스 중단 위험**이 있어 스크립트 스스로 조치를 보류하고 추가 환경변수를 요구한다. `remediate_approved.yml`의 `kisa_item_env` extra-var로 전달한다.

```
-e kisa_item_env='{"U-60":{"KISA_U60_NEW_COMMUNITY":"S3cr3t!"}}'
```

| 변수 | 대상 항목 | 용도 | 미지정 시 동작 |
|---|---|---|---|
| `KISA_U28_ALLOWED_IPS` | U-28 접속 IP 및 포트 제한 | TCP Wrappers 허용 IP 목록(콤마 구분) | 조치 보류(관리자 자신 접속 차단 방지) |
| `KISA_U40_ALLOWED_HOSTS` | U-40 NFS 접근 통제 | `/etc/exports` 허용 호스트(콤마 구분) | 전체 허용(`*`) 라인 그대로 둠 |
| `KISA_U47_TRUSTED_NETWORKS` | U-47 스팸 메일 릴레이 제한 | Postfix `mynetworks` 제한 대역 | `mynetworks` 값 변경 없이 `reject_unauth_destination`만 추가 |
| `KISA_U50_ALLOWED_TRANSFER_HOSTS` | U-50 DNS ZoneTransfer 설정 | 허용할 2차 네임서버 IP(콤마 구분) | 조치 보류(정상 2차 네임서버 차단 방지) |
| `KISA_U56_ALLOWED_IPS` | U-56 FTP 서비스 접근 제어 | FTP 접속 허용 IP(콤마 구분) | 조치 보류 |
| `KISA_U59_V3_USER` | U-59 안전한 SNMP 버전 사용 | 신규 SNMPv3 사용자명 | 조치 보류 |
| `KISA_U59_V3_AUTHPASS` | 〃 | SNMPv3 인증 암호(8자 이상) | 〃 (3개 변수 모두 필요) |
| `KISA_U59_V3_PRIVPASS` | 〃 | SNMPv3 암호화 암호(8자 이상) | 〃 |
| `KISA_U60_NEW_COMMUNITY` | U-60 SNMP Community String 복잡성 | 교체할 새 community string | 조치 보류(무작위 자동생성 시 관리자도 접근 불능 위험) |
| `KISA_U61_ALLOWED_SOURCE` | U-61 SNMP Access Control 설정 | 허용 소스 대역(CIDR) | 조치 보류 |

## 승인과 무관한 선택적 튜닝 변수

전체 파일시스템을 스캔하는 5개 항목은 스캔 제한시간을 조정할 수 있다(기본 20~30초, 초과 시 `fail`로 판정해 성급한 "양호" 오판을 방지). `KISA_APPROVAL`과 달리 승인 여부와 무관하며, 점검(`check`)·조치(`fix`) 스크립트 모두에 적용된다.

| 변수 | 대상 | 기본값 |
|---|---|---|
| `KISA_U15_SCAN_TIMEOUT` | U-15 소유자 없는 파일 | 30초 |
| `KISA_U23_SCAN_TIMEOUT` | U-23 SUID/SGID 파일 | 30초 |
| `KISA_U25_SCAN_TIMEOUT` | U-25 world writable 파일 | 30초 |
| `KISA_U26_SCAN_TIMEOUT` | U-26 /dev 밖 디바이스 파일 | 30초 |
| `KISA_U33_SCAN_TIMEOUT` | U-33 숨겨진 파일 | 20초 |

`environment:`에 필요한 항목만 추가하면 된다. 예:
```
-e kisa_item_env='{"U-25":{"KISA_U25_SCAN_TIMEOUT":"60"}}'
```
