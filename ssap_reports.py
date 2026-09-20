                       
"""
보안 점검 결과 → 'SaaS 대시보드 화면을 캡처한 듯한' 엑셀 리포트 생성기 (단독 실행)
================================================================================
openpyxl 기본 스타일을 버리고 아래 웹 UI 레이아웃 기법을 코드로 구현한다.

  1) 배경/카드 공간 분리 : 표지 전체를 연한 회색(#F3F4F6)으로 깔고,
     KPI·차트·표 영역만 순백색(#FFFFFF) 카드로 띄운다. 카드 사이엔
     좁은 빈 행/열(회색 거터)로 물리적 여백을 만든다.
  2) 타이포그래피 : 헤더 행높이 40 · Malgun Gothic 18 Bold · 남색 배경,
     KPI 숫자 28pt(취약 #E74C3C / 양호 #2ECC71) · 라벨 10pt 연한 회색(#64748B).
  3) 차트 환골탈태 : 외곽선 제거, 배경 흰색, 막대 단일 브랜드색(#3B82F6),
     막대 간격 확보, 데이터 표식 제거, 범례는 하단으로.
  4) 표 : 얇고 연한 회색(#E2E8F0) 선만, 세로 가운데 정렬 + 들여쓰기 여백.

실행:
    python3 ssap_reports.py
    python3 ssap_reports.py -o MyReport.xlsx
"""

import argparse
import io
import random
import unicodedata
from datetime import datetime
from typing import Any

import pandas as pd
import openpyxl
from openpyxl.chart import BarChart, DoughnutChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import DataPoint
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.drawing.line import LineProperties
from openpyxl.formatting.rule import CellIsRule, DataBarRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


                                                                    
           
                                                                    
FONT_NAME = "Malgun Gothic"

C_NAVY   = "3D74E4"          
C_CANVAS = "F3F4F6"                 
C_CARD   = "FFFFFF"           
C_LINE   = "E2E8F0"                 
C_LABEL  = "64748B"          
C_MUTED  = "94A3B8"       
C_BLUE   = "3B82F6"            
C_RED    = "E74C3C"       
C_GREEN  = "2ECC71"       
C_AMBER  = "F59E0B"
DONUT_PALETTE = [C_BLUE, C_RED, C_GREEN, C_AMBER, "8B5CF6", "14B8A6", C_MUTED]

FILL_VULN = PatternFill("solid", fgColor="FEF2F2")
FILL_SAFE = PatternFill("solid", fgColor="F0FDF4")


def F(size=10, bold=False, color="1F2937"):
    return Font(name=FONT_NAME, size=size, bold=bold, color=color)


HAIR = Side(style="thin", color=C_LINE)
BORDER = Border(left=HAIR, right=HAIR, top=HAIR, bottom=HAIR)

AL_LEFT   = Alignment(horizontal="left", vertical="center", indent=1)
AL_WRAP   = Alignment(horizontal="left", vertical="center", wrap_text=True, indent=1)
AL_CENTER = Alignment(horizontal="center", vertical="center")

HEADER_FILL = PatternFill("solid", fgColor=C_NAVY)
HEADER_FONT = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")

WRAP_COLS = {"진단 근거", "점검 현황", "진단 명령어 및 결과", "조치 가이드",
             "수집 파일 및 SHA-256", "실행 로그 요약", "사전점검", "무결성",
             "보안 위협 내용", "판단 기준", "항목명"}

STATUS_VULN, STATUS_SAFE, STATUS_NA = "취약", "양호", "N/A"
SEVERITY_ORDER = ["상", "중", "하"]


                                                                    
           
                                                                    
def generate_dummy_data():
    """실제로는 pd.read_json / pd.read_csv 로 대체. 여기선 재현 가능한 더미."""
    random.seed(42)
    servers = [
        {"ip": "100.120.178.40", "hostname": "WEBSERV-01"},
        {"ip": "100.120.178.41", "hostname": "WAS-01"},
        {"ip": "100.120.178.42", "hostname": "DB-01"},
        {"ip": "100.120.178.43", "hostname": "DB-02"},
        {"ip": "100.120.178.44", "hostname": "BATCH-01"},
    ]
    reference_data = [
        {"취약점 코드": "U-01", "항목명": "root 계정 원격 접속 제한", "진단 영역": "계정관리",
         "보안 위협 내용": "root 계정 원격 접속 허용 시 무차별 대입 공격으로 시스템 전체가 장악될 수 있다.",
         "판단 기준": "양호: PermitRootLogin no\n취약: PermitRootLogin yes 또는 미설정",
         "조치 가이드": "/etc/ssh/sshd_config 에서 PermitRootLogin no 로 변경 후 sshd 재시작"},
        {"취약점 코드": "U-02", "항목명": "패스워드 복잡성 설정", "진단 영역": "계정관리",
         "보안 위협 내용": "단순 패스워드는 사전/무차별 대입 공격으로 단시간에 노출된다.",
         "판단 기준": "양호: 영문·숫자·특수문자 3종 조합 8자리 이상\n취약: 정책 미설정",
         "조치 가이드": "/etc/security/pwquality.conf 에 minlen=8, minclass=3 설정"},
        {"취약점 코드": "U-03", "항목명": "불필요한 서비스 비활성화", "진단 영역": "서비스관리",
         "보안 위협 내용": "사용하지 않는 서비스의 알려진 취약점이 침투 경로가 된다.",
         "판단 기준": "양호: telnet/rsh 등 불필요 서비스 중지\n취약: 동작 중",
         "조치 가이드": "systemctl disable --now <service> 로 중지"},
        {"취약점 코드": "U-04", "항목명": "/etc/shadow 파일 소유자 및 권한", "진단 영역": "파일관리",
         "보안 위협 내용": "권한이 과도하면 비인가자가 패스워드 해시를 탈취해 크래킹할 수 있다.",
         "판단 기준": "양호: root 소유, 400 이하\n취약: 그 외",
         "조치 가이드": "chown root:root /etc/shadow && chmod 400 /etc/shadow"},
        {"취약점 코드": "U-05", "항목명": "최신 보안 패치 적용", "진단 영역": "패치관리",
         "보안 위협 내용": "미적용 보안 패치는 공개된 CVE 를 통한 원격 코드 실행에 노출된다.",
         "판단 기준": "양호: 가용 보안 업데이트 0건\n취약: 미적용 존재",
         "조치 가이드": "dnf/apt 로 보안 업데이트 적용 및 정기 패치 주기 수립"},
        {"취약점 코드": "U-06", "항목명": "su 명령어 사용 제한", "진단 영역": "계정관리",
         "보안 위협 내용": "su 제한이 없으면 탈취된 일반 계정이 곧바로 root 권한 상승을 시도한다.",
         "판단 기준": "양호: wheel 그룹만 su 허용\n취약: 전체 허용",
         "조치 가이드": "/etc/pam.d/su 에서 pam_wheel.so use_uid 활성화"},
        {"취약점 코드": "U-07", "항목명": "주요 로그 파일 권한 설정", "진단 영역": "로그관리",
         "보안 위협 내용": "로그 권한이 느슨하면 침해 흔적이 변조·삭제될 수 있다.",
         "판단 기준": "양호: 640 이하\n취약: 640 초과",
         "조치 가이드": "chmod 640 /var/log/secure /var/log/messages"},
        {"취약점 코드": "U-08", "항목명": "원격 로그 서버 전송", "진단 영역": "로그관리",
         "보안 위협 내용": "로컬 로그만 유지하면 공격자가 시스템 장악 후 로그를 지운다.",
         "판단 기준": "양호: rsyslog 원격 전송(@@) 규칙 존재\n취약: 없음",
         "조치 가이드": "/etc/rsyslog.conf 에 '*.* @@logserver:514' 추가"},
    ]

    rows = []
    for s in servers:
        for ref in reference_data:
            status = random.choices([STATUS_SAFE, STATUS_VULN, STATUS_NA],
                                    weights=[0.58, 0.32, 0.10])[0]
            severity = random.choice(SEVERITY_ORDER)
            cmd = ("grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
                   if ref["취약점 코드"] == "U-01" else "점검 스크립트 실행")
            outcome = {
                STATUS_SAFE: "설정 값이 기준에 부합함 (양호)",
                STATUS_VULN: "기준 위반 값 확인됨 (취약)",
                STATUS_NA:   "점검 대상 파일/서비스 없음 (N/A)",
            }[status]
            rows.append({
                "자산 IP": s["ip"], "호스트명": s["hostname"],
                "취약점 코드": ref["취약점 코드"], "진단 영역": ref["진단 영역"],
                "중요도": severity, "항목명": ref["항목명"], "상태": status,
                "진단 명령어 및 결과": f"$ {cmd}\n{outcome}",
                "진단 근거": f"[{s['hostname']}] {ref['판단 기준'].splitlines()[0]} → '{status}' 판정.",
                "점검 현황": f"수집 2026-08-28\n----\n{outcome}\n----",
                "조치 가이드": ref["조치 가이드"],
                "조치 담당자": "", "조치 상태": "",
            })
    return pd.DataFrame(rows), pd.DataFrame(reference_data)


def _flatten(value: Any) -> str:
    """DB의 dict/list 증적 값을 엑셀 셀에 넣을 수 있는 문자열로 바꾼다."""
    if isinstance(value, dict):
        return "\n".join(f"- {key}: {_flatten(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return "\n".join(f"- {_flatten(item)}" for item in value)
    return "" if value is None else str(value)


def _domain_from_record(record: dict[str, Any]) -> str:
    domain = str(record.get("domain") or "").strip().upper()
    if domain:
        return domain
    code = str(record.get("code") or "").strip().upper()
    if code.startswith("WEB-"):
        return "WEB"
    if code.startswith("D-"):
        return "DBMS"
    if code.startswith("U-"):
        return "UNIX"
    return "미분류"


def records_to_frames(
    results: list[dict[str, Any]],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """백엔드 DB 레코드를 프리뷰 레이아웃이 사용하는 두 표로 변환한다."""
    rows: list[dict[str, Any]] = []
    references: dict[str, dict[str, Any]] = {}

    for record in results:
        code = str(record.get("code") or "-")
        title = str(record.get("title") or record.get("name") or "-")
        detail = str(record.get("detail") or record.get("rationale") or "").strip()
        evidence = _flatten(
            record.get("evidence_data")
            if record.get("evidence_data") is not None
            else record.get("evidenceData")
        ).strip()
        status = str(record.get("status") or STATUS_NA).strip()
        if status not in {STATUS_SAFE, STATUS_VULN, STATUS_NA}:
            status = STATUS_NA
        severity = str(record.get("severity") or "중").strip()
        if severity not in SEVERITY_ORDER:
            severity = "중"
        domain = _domain_from_record(record)
        timestamp = str(record.get("timestamp") or record.get("saved_at") or "").strip()
        impact = str(record.get("impact") or "").strip()
        action_tag = str(record.get("action_tag") or record.get("action") or "").strip()
        guide = str(
            record.get("remediation")
            or record.get("remediation_guide")
            or record.get("guide")
            or action_tag
        ).strip()

        rows.append({
            "자산 IP": str(record.get("ip") or "-"),
            "호스트명": str(record.get("host") or "-"),
            "취약점 코드": code,
            "진단 영역": domain,
            "중요도": severity,
            "항목명": title,
            "상태": status,
            "진단 명령어 및 결과": evidence if evidence else "기록 없음",
            "진단 근거": detail if detail else "내용 없음",
            "점검 현황": f"점검 시각: {timestamp}" if timestamp else "-",
            "조치 가이드": guide,
            "조치 담당자": "",
            "조치 상태": action_tag,
        })
        references.setdefault(code, {
            "취약점 코드": code,
            "항목명": title,
            "진단 영역": domain,
            "보안 위협 내용": impact,
            "판단 기준": detail,
            "조치 가이드": guide,
        })

    if not rows:
        rows.append({
            "자산 IP": "점검 결과 없음", "호스트명": "-",
            "취약점 코드": "-", "진단 영역": "미분류", "중요도": "중",
            "항목명": "저장된 점검 결과가 없습니다.", "상태": STATUS_NA,
            "진단 명령어 및 결과": "", "진단 근거": "", "점검 현황": "",
            "조치 가이드": "", "조치 담당자": "", "조치 상태": "",
        })
        references["-"] = {
            "취약점 코드": "-", "항목명": "점검 결과 없음", "진단 영역": "미분류",
            "보안 위협 내용": "", "판단 기준": "", "조치 가이드": "",
        }

    return pd.DataFrame(rows), pd.DataFrame(references.values())


                                                                    
                                           
                                                                    
def _disp_width(text):
    longest = 0
    for line in str(text).split("\n"):
        w = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in line)
        longest = max(longest, w)
    return longest


def write_table(wb, sheet_name, df, min_w=11, max_w=52):
    ws = wb.create_sheet(sheet_name)
    ws.sheet_view.showGridLines = False

    headers = list(df.columns)
    ws.append(headers)
    for row in df.itertuples(index=False, name=None):
        ws.append(["" if pd.isna(v) else v for v in row])

    n_rows, n_cols = df.shape
    last_col = get_column_letter(n_cols)
    wrap_idx = {i + 1 for i, h in enumerate(headers) if h in WRAP_COLS}

    for c in range(1, n_cols + 1):
        cell = ws.cell(row=1, column=c)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = AL_CENTER
        cell.border = BORDER
    ws.row_dimensions[1].height = 30

    for r in range(2, n_rows + 2):
        for c in range(1, n_cols + 1):
            cell = ws.cell(row=r, column=c)
            cell.font = F(size=10)
            cell.border = BORDER
            cell.alignment = AL_WRAP if c in wrap_idx else AL_LEFT

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{last_col}{max(n_rows + 1, 1)}"

    for idx in range(1, n_cols + 1):
        width = max([_disp_width(ws.cell(row=r, column=idx).value)
                     for r in range(1, n_rows + 2)] or [10])
        cap = 46 if idx in wrap_idx else max_w
        ws.column_dimensions[get_column_letter(idx)].width = min(max(width + 3, min_w), cap)
    return ws


                                                                    
                                            
                                                                    
def _fill_range(ws, rng, color):
    pf = PatternFill("solid", fgColor=color)
    for row in ws[rng]:
        for cell in row:
            cell.fill = pf


def _card(ws, rng):
    """흰색 카드 배경 + 연회색 외곽선."""
    _fill_range(ws, rng, C_CARD)
    for row in ws[rng]:
        for cell in row:
            cell.border = BORDER


def _chart_chrome(chart):
    """외곽선 제거 + 배경 흰색 + plot area 투명 + 범례 하단."""
    gp = GraphicalProperties(solidFill=C_CARD)
    gp.line = LineProperties(noFill=True)
    chart.graphical_properties = gp

    pa = GraphicalProperties()
    pa.noFill = True
    pa.line = LineProperties(noFill=True)
    chart.plot_area.graphicalProperties = pa

    if chart.legend is not None:
        chart.legend.position = "b"
        chart.legend.overlay = False


def create_dashboard(wb, df):
    ws = wb.create_sheet("표지 (Dashboard)")
    ws.sheet_view.showGridLines = False

    for col in "BCDEFGHIJKLMNOPQ":
        ws.column_dimensions[col].width = 11
    ws.column_dimensions["A"].width = 3
    ws.column_dimensions["R"].width = 3

    canvas = "A1:R65"
    _fill_range(ws, canvas, C_CANVAS)
    for r in range(1, 66):
        ws.row_dimensions[r].height = 18
    
    ws.row_dimensions[2].height = 42
    ws.merge_cells("B2:M2")
    ws["B2"] = "📊 종합 보안 점검 대시보드"
    ws["B2"].font = Font(name=FONT_NAME, size=20, bold=True, color="FFFFFF")
    ws["B2"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    
    ws.merge_cells("N2:Q2")
    ws["N2"] = f"생성일시: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    ws["N2"].font = Font(name=FONT_NAME, size=11, color="FFFFFF", bold=True)
    ws["N2"].alignment = Alignment(horizontal="right", vertical="center", indent=1)
    _fill_range(ws, "B2:Q2", C_NAVY)

    n_servers = df["자산 IP"].nunique()
    n_total = len(df)
    n_safe = int((df["상태"] == STATUS_SAFE).sum())
    n_vuln = int((df["상태"] == STATUS_VULN).sum())
    valid = n_safe + n_vuln
    comp = round(n_safe / valid * 100, 1) if valid else 0.0

    cards = [
        ("B", "E", "점검 대상 서버", f"{n_servers} 대", "인프라 자산", "3D74E4"),
        ("F", "I", "총 점검 항목", f"{n_total} 건", "N/A 포함", "3D74E4"),
        ("J", "M", "통합 보안 준수율", f"{comp} %", f"양호 {n_safe}건", C_GREEN),
        ("N", "Q", "발견된 취약점", f"{n_vuln} 건", "조치 필요", C_RED),
    ]
    
    for c1, c2, label, value, caption, color in cards:
        rng = f"{c1}4:{c2}7"
        _card(ws, rng)
        ws.merge_cells(f"{c1}4:{c2}4")
        ws.merge_cells(f"{c1}5:{c2}6")
        ws.merge_cells(f"{c1}7:{c2}7")
        
        ws[f"{c1}4"] = label
        ws[f"{c1}4"].font = F(size=11, bold=True, color=C_LABEL)
        ws[f"{c1}4"].alignment = Alignment(horizontal="center", vertical="center")
        
        ws[f"{c1}5"] = value
        ws[f"{c1}5"].font = Font(name=FONT_NAME, size=24, bold=True, color=color)
        ws[f"{c1}5"].alignment = Alignment(horizontal="center", vertical="center")
        
        ws[f"{c1}7"] = caption
        ws[f"{c1}7"].font = F(size=10, color=C_MUTED)
        ws[f"{c1}7"].alignment = Alignment(horizontal="center", vertical="center")

    wd = wb.create_sheet("_chart_data")
    wd.sheet_state = "hidden"
    vuln_df = df[df["상태"] == STATUS_VULN]
    
    # 1. Domain Vulnerability Rate
    all_dom = list(df["진단 영역"].drop_duplicates())
    rate_by_dom = {}
    for d in all_dom:
        sub = df[df["진단 영역"] == d]
        safe = (sub["상태"] == STATUS_SAFE).sum()
        vuln = (sub["상태"] == STATUS_VULN).sum()
        denom = safe + vuln
        rate_by_dom[d] = round((vuln / denom * 100), 1) if denom > 0 else 0.0
        
    wd["A1"], wd["B1"] = "진단 영역", "취약률(%)"
    for i, (k, v) in enumerate(rate_by_dom.items(), start=2):
        wd.cell(row=i, column=1, value=k)
        wd.cell(row=i, column=2, value=v)
    nd = len(rate_by_dom)
    
    # 2. Severity
    by_sev = vuln_df["중요도"].value_counts().reindex(["상", "중", "하"], fill_value=0)
    wd["D1"], wd["E1"] = "위험도", "취약 건수"
    for i, (k, v) in enumerate(by_sev.items(), start=2):
        wd.cell(row=i, column=4, value=k)
        wd.cell(row=i, column=5, value=int(v))
    
    # 3. Top Servers
    top_servers = vuln_df["호스트명"].value_counts().head(5)
    wd["G1"], wd["H1"] = "서버명", "취약 건수"
    for i, (k, v) in enumerate(top_servers.items(), start=2):
        wd.cell(row=i, column=7, value=k)
        wd.cell(row=i, column=8, value=int(v))
    nts = len(top_servers)
    
    # --- CHART 1 (Domain Rate) ---
    _card(ws, "B9:F32")
    dom_chart = BarChart()
    dom_chart.type = "col"
    dom_chart.title = "영역별 취약률 (%)"
    dom_chart.height, dom_chart.width = 11.5, 9.0
    dom_chart.gapWidth = 120
    dom_chart.legend = None
    if nd > 0:
        dom_chart.add_data(Reference(wd, min_col=2, min_row=1, max_row=1 + nd), titles_from_data=True)
        dom_chart.set_categories(Reference(wd, min_col=1, min_row=2, max_row=1 + nd))
        domain_colors = {"UNIX": "475569", "DBMS": "0369A1", "WEB": "6D28D9", "NETWORK": "14B8A6", "SECURITY": "F59E0B"}
        dom_keys = list(rate_by_dom.keys())
        for i in range(nd):
            pt = DataPoint(idx=i)
            pt.graphicalProperties = GraphicalProperties(solidFill=domain_colors.get(dom_keys[i], DONUT_PALETTE[i % len(DONUT_PALETTE)]))
            dom_chart.series[0].dPt.append(pt)
        dom_chart.dLbls = DataLabelList(showVal=True)
    dom_chart.y_axis.delete = False
    dom_chart.x_axis.delete = False
    _chart_chrome(dom_chart)
    ws.add_chart(dom_chart, "B10")

    # --- CHART 2 (Severity) ---
    _card(ws, "G9:L32")
    bar1 = BarChart()
    bar1.type = "col"
    bar1.title = "위험도별 취약 현황 (건)"
    bar1.height, bar1.width = 11.5, 11.5
    bar1.gapWidth = 150
    bar1.legend = None
    bar1.add_data(Reference(wd, min_col=5, min_row=1, max_row=4), titles_from_data=True)
    bar1.set_categories(Reference(wd, min_col=4, min_row=2, max_row=4))
    for i, color in enumerate([C_RED, "F97316", "EAB308"]):
        pt = DataPoint(idx=i); pt.graphicalProperties = GraphicalProperties(solidFill=color)
        bar1.series[0].dPt.append(pt)
    bar1.dLbls = DataLabelList(showVal=True)
    bar1.y_axis.delete = False
    bar1.x_axis.delete = False
    _chart_chrome(bar1)
    ws.add_chart(bar1, "G10")
    
    # --- CHART 3 (Top Servers) ---
    _card(ws, "M9:Q32")
    bar2 = BarChart()
    bar2.type = "bar"
    bar2.title = "취약 서버 TOP 5 (건)"
    bar2.height, bar2.width = 11.5, 9.5
    bar2.gapWidth = 100
    bar2.legend = None
    if nts > 0:
        bar2.add_data(Reference(wd, min_col=8, min_row=1, max_row=1 + nts), titles_from_data=True)
        bar2.set_categories(Reference(wd, min_col=7, min_row=2, max_row=1 + nts))
        bar2.series[0].graphicalProperties = GraphicalProperties(solidFill="8B5CF6")
    bar2.dLbls = DataLabelList(showVal=True)
    bar2.y_axis.delete = False
    bar2.x_axis.delete = False
    _chart_chrome(bar2)
    ws.add_chart(bar2, "M10")

    dom = (df.groupby("진단 영역")["상태"]
             .agg(총항목="count",
                  양호=lambda s: int((s == STATUS_SAFE).sum()),
                  취약=lambda s: int((s == STATUS_VULN).sum()))
             .reindex(all_dom).reset_index())
    denom = (dom["양호"] + dom["취약"])
    dom["준수율(%)"] = (dom["양호"].div(denom.where(denom != 0)) * 100).fillna(0.0).round(1)
    
    _card(ws, f"B34:I{35 + len(dom)}")
    ws.merge_cells("B34:I34")
    ws["B34"] = "📑 진단 영역별 세부 현황"
    ws["B34"].font = F(size=11, bold=True, color=C_LABEL)
    ws["B34"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    
    headers1 = ["진단 영역", "총항목", "양호", "취약", "준수율(%)"]
    col_mapping = [2, 5, 6, 7, 8]
    for i, h in enumerate(headers1):
        if h == "진단 영역":
            ws.merge_cells("B35:D35")
            c = ws.cell(row=35, column=2, value=h)
        else:
            if h == "준수율(%)": ws.merge_cells("H35:I35")
            c = ws.cell(row=35, column=col_mapping[i], value=h)
        c.fill = HEADER_FILL; c.font = HEADER_FONT; c.alignment = AL_CENTER; c.border = BORDER
        
    for r_idx, row in enumerate(dom[headers1].itertuples(index=False, name=None), start=36):
        ws.merge_cells(f"B{r_idx}:D{r_idx}")
        c_dom = ws.cell(row=r_idx, column=2, value=row[0])
        c_dom.alignment = AL_LEFT; c_dom.font = F(size=10); c_dom.border = BORDER
        ws.cell(row=r_idx, column=3).border = BORDER; ws.cell(row=r_idx, column=4).border = BORDER
        for i, val in enumerate(row[1:], start=1):
            if headers1[i] == "준수율(%)": 
                ws.merge_cells(f"H{r_idx}:I{r_idx}")
                ws.cell(row=r_idx, column=9).border = BORDER
            c = ws.cell(row=r_idx, column=col_mapping[i], value=val)
            c.alignment = AL_CENTER; c.font = F(size=10); c.border = BORDER

    top_v = vuln_df.groupby(["취약점 코드", "항목명", "진단 영역"]).size().reset_index(name="발생 건수")
    top_v = top_v.sort_values("발생 건수", ascending=False).head(5)
    
    _card(ws, f"K34:Q{35 + len(top_v)}")
    ws.merge_cells("K34:Q34")
    ws["K34"] = "🔥 가장 많이 발견된 취약점 TOP 5"
    ws["K34"].font = F(size=11, bold=True, color=C_LABEL)
    ws["K34"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    
    headers2 = ["코드", "진단 영역", "취약 항목명", "건수"]
    c_map = [11, 12, 13, 17]
    for i, h in enumerate(headers2):
        if h == "취약 항목명": ws.merge_cells("M35:P35")
        c = ws.cell(row=35, column=c_map[i], value=h)
        c.fill = HEADER_FILL; c.font = HEADER_FONT; c.alignment = AL_CENTER; c.border = BORDER
        if h == "취약 항목명":
            ws.cell(row=35, column=14).border=BORDER; ws.cell(row=35, column=15).border=BORDER; ws.cell(row=35, column=16).border=BORDER
        
    for r_idx, row in enumerate(top_v.itertuples(index=False, name=None), start=36):
        c1 = ws.cell(row=r_idx, column=11, value=row[0]); c1.alignment = AL_CENTER; c1.font=F(size=9); c1.border=BORDER
        c2 = ws.cell(row=r_idx, column=12, value=row[2]); c2.alignment = AL_CENTER; c2.font=F(size=9); c2.border=BORDER
        ws.merge_cells(f"M{r_idx}:P{r_idx}")
        c3 = ws.cell(row=r_idx, column=13, value=row[1]); c3.alignment = Alignment(horizontal="left", vertical="center", wrapText=True); c3.font=F(size=9); c3.border=BORDER
        ws.cell(row=r_idx, column=14).border=BORDER; ws.cell(row=r_idx, column=15).border=BORDER; ws.cell(row=r_idx, column=16).border=BORDER
        c4 = ws.cell(row=r_idx, column=17, value=row[3]); c4.alignment = AL_CENTER; c4.font=F(size=9, bold=True, color=C_RED); c4.border=BORDER

    return ws


                                                                    
                             
                                                                    
def create_asset_status(wb, df):
    grp = df.groupby(["자산 IP", "호스트명"])["상태"]
    tbl = grp.agg(
        할당된_항목_수="count",
        양호_건수=lambda s: int((s == STATUS_SAFE).sum()),
        취약_건수=lambda s: int((s == STATUS_VULN).sum()),
    ).reset_index()
    denom = (tbl["양호_건수"] + tbl["취약_건수"])
    tbl["보안 준수율(%)"] = (tbl["양호_건수"].div(denom.where(denom != 0)) * 100).fillna(0.0).round(1)
    tbl = tbl.rename(columns={"할당된_항목_수": "할당된 항목 수",
                              "양호_건수": "양호 건수", "취약_건수": "취약 건수"})
    tbl = tbl[["자산 IP", "호스트명", "할당된 항목 수",
               "양호 건수", "취약 건수", "보안 준수율(%)"]].sort_values("자산 IP").reset_index(drop=True)

    ws = write_table(wb, "자산현황 목록", tbl)
    n_rows = len(tbl)
    for idx in range(3, 7):
        for r in range(2, n_rows + 2):
            ws.cell(row=r, column=idx).alignment = AL_CENTER

    rate_letter = get_column_letter(6)
    ws.conditional_formatting.add(
        f"{rate_letter}2:{rate_letter}{n_rows + 1}",
        DataBarRule(start_type="num", start_value=0, end_type="num", end_value=100,
                    color=C_BLUE, showValue=True),
    )
    return ws


                                                                    
                              
                                                                    
def create_action_items(wb, df):
    v = df[df["상태"] == STATUS_VULN].copy()
    v = v.sort_values(["중요도", "자산 IP", "취약점 코드"],
                      key=lambda s: s.map({"상": 0, "중": 1, "하": 2})
                      if s.name == "중요도" else s)
    action = pd.DataFrame({
        "자산 IP": v["자산 IP"], "호스트명": v["호스트명"], "취약점 코드": v["취약점 코드"], "중요도": v["중요도"],
        "항목명": v["항목명"], "진단 근거": v["진단 근거"], "조치 가이드": v["조치 가이드"],
        "조치 담당자": "", "조치 상태": "",
    }).reset_index(drop=True)

    ws = write_table(wb, "취약 목록 모아보기", action)
    sev_idx = list(action.columns).index("중요도") + 1
    for r in range(2, len(action) + 2):
        c = ws.cell(row=r, column=sev_idx)
        c.alignment = AL_CENTER
        if c.value == "상":
            c.font = F(size=10, bold=True, color=C_RED)
    for name in ("조치 담당자", "조치 상태"):
        ci = list(action.columns).index(name) + 1
        for r in range(2, len(action) + 2):
            ws.cell(row=r, column=ci).fill = PatternFill("solid", fgColor="FFFDE7")
    return ws


                                                                    
                          
                                                                    
def create_server_details(wb, df):
    cols = ["취약점 코드", "진단 영역", "중요도", "항목명", "상태",
            "진단 명령어 및 결과", "진단 근거", "점검 현황"]
    made = []
    for ip in sorted(df["자산 IP"].unique()):
        sub = (df[df["자산 IP"] == ip][cols]
               .sort_values(["진단 영역", "취약점 코드"]).reset_index(drop=True))
        ws = write_table(wb, ip, sub)
        letter = get_column_letter(cols.index("상태") + 1)
        rng = f"{letter}2:{letter}{len(sub) + 1}"
        ws.conditional_formatting.add(
            rng, CellIsRule(operator="equal", formula=['"취약"'],
                            fill=FILL_VULN, font=F(size=10, bold=True, color=C_RED)))
        ws.conditional_formatting.add(
            rng, CellIsRule(operator="equal", formula=['"양호"'],
                            fill=FILL_SAFE, font=F(size=10, bold=True, color=C_GREEN)))
        for r in range(2, len(sub) + 2):
            ws.cell(row=r, column=cols.index("상태") + 1).alignment = AL_CENTER
        made.append(ip)
    return made


                                                                    
                          
                                                                    
def create_reference_guide(wb, ref_df):
    ref = ref_df[["취약점 코드", "항목명", "보안 위협 내용", "판단 기준"]].copy()
    return write_table(wb, "진단 기준 가이드", ref)

def create_evidence_sheet(wb, evidence: list[dict[str, Any]]):
    ws=wb.create_sheet("작업 증적")
    ws.sheet_view.showGridLines=False
    ws.merge_cells("A1:H1");title=ws["A1"];title.value="작업 증적 및 무결성 검증"
    title.font=Font(name=FONT_NAME,size=18,bold=True,color="FFFFFF")
    title.fill=PatternFill("solid",fgColor=C_NAVY);title.alignment=Alignment(vertical="center")
    ws.row_dimensions[1].height=34
    headers=["작업 ID","유형","대상","수집 시각","사전점검","무결성","수집 파일 및 SHA-256","실행 로그 요약"]
    for column,label in enumerate(headers,1):
        cell=ws.cell(3,column,label);cell.font=Font(name=FONT_NAME,bold=True,color="FFFFFF")
        cell.fill=PatternFill("solid",fgColor="3D74E4");cell.alignment=Alignment(horizontal="center",vertical="center")
    if not evidence:
        ws.merge_cells("A4:H4");ws["A4"]="연결된 작업 증적이 없습니다.";ws["A4"].alignment=Alignment(horizontal="center")
    for row_index,item in enumerate(evidence[:20],4):
        preflight=item.get("preflight") or {};files=item.get("files") or []
        collected=item.get("collected_at")
        collected_text=datetime.fromtimestamp(collected).astimezone().strftime("%Y-%m-%d %H:%M:%S") if collected else "-"
        file_text="\n".join(f"{'검증' if f.get('verified') else '불일치'} · {f.get('path','-')}\n{f.get('sha256','-')}" for f in files)
        values=[item.get("job_id","-"),item.get("kind","-"),", ".join(item.get("targets") or []) or "-",
          collected_text,
          f"{preflight.get('passed',0)}/{preflight.get('total',0)} 통과",
          "검증 완료" if item.get("integrity_ok") else "검증 실패",
          file_text or "수집 파일 없음","\n".join(item.get("log_tail") or []) or "-"]
        for column,value in enumerate(values,1):
            cell=ws.cell(row_index,column,value);cell.font=Font(name=FONT_NAME,size=9,color="0F172A")
            cell.alignment=Alignment(vertical="top",wrap_text=True)
            cell.fill=PatternFill("solid",fgColor="F8FAFC" if row_index%2==0 else "FFFFFF")
        ws.row_dimensions[row_index].height=min(180,max(42,15*(max(len(files)*2,len(item.get("log_tail") or []),2))))
    widths=[16,12,22,20,13,13,58,65]
    for index,width in enumerate(widths,1):ws.column_dimensions[get_column_letter(index)].width=width
    ws.freeze_panes="A4";ws.auto_filter.ref=f"A3:H{max(3,3+min(len(evidence),20))}"
    return ws


                                                                    
           
                                                                    
def build_workbook(df: pd.DataFrame, ref_df: pd.DataFrame, evidence: list[dict[str, Any]] | None = None):
    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    create_dashboard(wb, df)
    create_asset_status(wb, df)
    create_action_items(wb, df)
    create_server_details(wb, df)
    create_reference_guide(wb, ref_df)
    create_evidence_sheet(wb,evidence or [])
    return wb


def build_report_bytes(results: list[dict[str, Any]], evidence: list[dict[str, Any]] | None = None) -> bytes:
    """현재 DB 결과를 ssap_reports_preview와 같은 생성 코드로 만든다."""
    df, ref_df = records_to_frames(results)
    wb = build_workbook(df, ref_df, evidence)
    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def generate_report(output_file="ssap_reports_preview.xlsx"):
    df, ref_df = generate_dummy_data()
    wb = build_workbook(df, ref_df)
    servers = sorted(df["자산 IP"].unique())

    wb.save(output_file)
    print(f"[완료] {output_file}")
    print(f"  시트: [표지 (Dashboard)] [자산현황 목록] [취약 목록 모아보기] "
          f"{servers} [진단 기준 가이드]  (숨김 _chart_data)")
    print(f"  점검 {len(df)}건 · 양호 {(df['상태'] == '양호').sum()} · "
          f"취약 {(df['상태'] == '취약').sum()} · N/A {(df['상태'] == 'N/A').sum()}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="엑셀형 보안 대시보드 리포트 생성기")
    ap.add_argument("-o", "--output", default="ssap_reports_preview.xlsx")
    generate_report(ap.parse_args().output)
