<p align="center">
  <h1 align="center">security-framework-mcp</h1>
  <p align="center">
    <strong>OWASP + NIST 통합 보안 프레임워크 MCP 서버</strong>
  </p>
  <p align="center">
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP Compatible"></a>
  </p>
  <p align="center">
    <a href="./README.md">English</a>
  </p>
</p>

---

**3,329개 보안 데이터**를 단일 MCP 인터페이스로 검색 — **OWASP** (Top 10, API/LLM/MCP Top 10, ASVS 5.0, WSTG, MASVS, Proactive Controls, 113+ Cheat Sheets, 418+ 프로젝트)와 **NIST** (SP 800-53 1,196개 컨트롤 + 53A 평가 + 53B 기준선, CSF 2.0, Privacy Framework 1.0, SP 800-37 RMF, 613개 출판물, CMVP, NICE) — **실시간 NVD/CVE**, 컴플라이언스 매핑, STRIDE 위협 모델링, MCP 보안 평가 포함.

## 빠른 시작

```bash
pip install git+https://github.com/zer0-kr/security-framework-mcp.git
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security": {
      "command": "security-framework-mcp"
    }
  }
}
```

첫 실행 시 로컬 데이터베이스가 자동으로 생성됩니다 (~15-20초). 이후 주 1회 자동 갱신.

## 데이터 소스 (19개 로컬 + 1개 실시간)

### OWASP (11개)

| 소스 | 레코드 | 설명 |
|------|--------|------|
| **프로젝트** | 418 | Flagship/Production/Lab/Incubator 전체 |
| **ASVS 5.0** | 345 | 애플리케이션 보안 검증 표준 |
| **WSTG** | 111 | 웹 보안 테스트 가이드 |
| **Top 10 2021** | 10 | 웹 10대 보안 위험 + CWE 매핑 |
| **API Top 10 2023** | 10 | API 보안 위험 |
| **LLM Top 10 2025** | 10 | AI/LLM 보안 위험 |
| **MCP Top 10 2025** | 10 | MCP 서버 보안 위험 |
| **Proactive Controls 2024** | 10 | 개발자 방어 통제 |
| **MASVS** | 23 | 모바일 앱 보안 검증 표준 |
| **CWE 데이터베이스** | 39 | 주요 CWE + OWASP 교차 참조 |
| **Cheat Sheets** | 113+ | 보안 구현 가이드 (온디맨드) |

### NIST (8개)

| 소스 | 레코드 | 설명 |
|------|--------|------|
| **SP 800-53 Rev. 5** | 1,196 | 보안/프라이버시 컨트롤 + **53A 평가 목표/방법** + **53B 기준선(LOW/MODERATE/HIGH)** |
| **CSF 2.0** | 225 | 사이버보안 프레임워크 (6개 기능, 22개 카테고리, 197개 서브카테고리) |
| **Privacy Framework 1.0** | 92 | 프라이버시 프레임워크 (5개 기능) |
| **SP 800-37 RMF** | 7 | 위험 관리 프레임워크 (7단계 프로세스) |
| **출판물** | 613 | NIST 사이버보안 전체 출판물 (SP 800, FIPS, IR, CSWP) |
| **용어사전** | 39 | 사이버보안 핵심 용어 |
| **CMVP** | 15 | FIPS 140 인증 암호 모듈 |
| **NICE** | 43 | 사이버보안 인력 프레임워크 직무 역할 |

### 실시간: NVD CVE API 2.0

## 도구 (33개)

### OWASP 도구

| 도구 | 설명 |
|------|------|
| `list_projects` | 418+ 프로젝트 목록 (레벨/타입 필터) |
| `search_projects` | 프로젝트 전문 검색 |
| `get_project` | 프로젝트 상세 정보 |
| `get_asvs` | ASVS 5.0 요구사항 (챕터/레벨/검색 필터) |
| `get_wstg` | WSTG 테스트 케이스 (카테고리/검색 필터) |
| `get_top10` | Top 10 2021 + CWE 매핑 |
| `get_api_top10` | API Security Top 10 2023 |
| `get_llm_top10` | LLM Top 10 2025 |
| `get_mcp_top10` | MCP Top 10 2025 |
| `get_proactive_controls` | Proactive Controls 2024 |
| `get_masvs` | MASVS 모바일 보안 통제 |
| `get_cheatsheet` | 113+ Cheat Sheets |

### NIST 도구

| 도구 | 설명 |
|------|------|
| `search_nist` | 8개 NIST 소스 통합 검색 |
| `get_nist_control` | SP 800-53 컨트롤 조회 — 문장, 가이드, **53A 평가**, **53B 기준선** 필터 (LOW/MODERATE/HIGH), 패밀리 필터 |
| `get_nist_csf` | CSF 2.0 기능/카테고리/서브카테고리 |
| `get_nist_pf` | Privacy Framework 1.0 |
| `get_nist_rmf` | SP 800-37 RMF 단계별 태스크 |
| `get_nist_publication` | 613개 출판물 검색/조회 |
| `get_nist_glossary` | 사이버보안 용어 정의 |
| `get_nist_cmvp` | FIPS 140 인증 모듈 |
| `get_nice_roles` | NICE 직무 역할 |

### 취약점 & CWE

| 도구 | 설명 |
|------|------|
| `get_cwe` | CWE 조회 + OWASP 자동 교차 참조 |
| `search_cve` | 실시간 NVD CVE 검색 |
| `get_cve_detail` | CVE 상세 정보 (CVSS, 약점, 참조) |

### 분석 & 평가

| 도구 | 설명 |
|------|------|
| `search_owasp` | 19개 소스 통합 검색 (OWASP + NIST) |
| `cross_reference` | CWE → Top 10 / ASVS / WSTG 교차 참조 |
| `compliance_map` | ASVS → PCI-DSS 4.0 / ISO 27001:2022 / NIST 800-53 매핑 |
| `assess_stack` | 기술 스택 보안 진단 |
| `generate_checklist` | 보안 체크리스트 생성 (프로젝트 타입 × 깊이) |
| `assess_mcp_security` | MCP 서버 보안 평가 (MCP Top 10 기준) |
| `threat_model` | STRIDE 위협 모델링 |
| `update_database` | 인덱스 재빌드 |
| `database_status` | DB 상태 확인 |

## 프롬프트 템플릿 (4개)

| 프롬프트 | 설명 |
|---------|------|
| `security_review` | OWASP + NIST 기반 보안 리뷰 워크플로우 |
| `threat_analysis` | 위협 분석 — CWE 매핑, 컨트롤 추천 |
| `compliance_check` | 컴플라이언스 평가 — ASVS + 테스트 절차 |
| `secure_code_review` | 코드 보안 리뷰 — CWE ID + 안전한 대안 |

## 사용 예시

```
> OWASP와 NIST 전체에서 "접근 제어"를 검색해줘

> NIST SP 800-53 AC-1 컨트롤을 보여줘

> CSF 2.0의 Protect 기능 카테고리를 보여줘

> SP 800-53 LOW 기준선에 포함된 컨트롤 목록

> Privacy Framework 1.0의 Control-P 기능을 보여줘

> SP 800-37 RMF의 ASSESS 단계를 설명해줘

> CWE-79를 OWASP와 NIST 표준으로 교차 참조해줘

> ASVS V4를 PCI-DSS, ISO 27001, NIST 800-53에 매핑해줘

> 내 스택(React, Node.js, PostgreSQL, REST API)의 보안을 진단해줘

> 웹 API 프로젝트용 보안 체크리스트를 생성해줘

> 내 MCP 서버 보안을 평가해줘: shell exec, 인증 없음, 커뮤니티 플러그인

> NVD에서 critical log4j CVE를 검색해줘

> STRIDE 위협 모델을 생성해줘: 결제 API, JWT 인증, PostgreSQL
```

## 설정

| 환경변수 | 기본값 | 설명 |
|---------|--------|------|
| `SECURITY_MCP_DATA_DIR` | `~/.security-framework-mcp` | 로컬 DB 디렉토리 |
| `SECURITY_MCP_UPDATE_INTERVAL` | `604800` (7일) | 자동 갱신 주기 (초) |
| `NVD_API_KEY` | _(없음)_ | NVD API 키 (선택, 속도 향상) |

## 개발

```bash
git clone https://github.com/zer0-kr/security-framework-mcp.git
cd security-framework-mcp
pip install -e ".[dev]"
python -m pytest tests/test_unit_db.py tests/test_unit_collectors.py -v
python tests/test_comprehensive.py
```

## 기여

1. Fork → 2. 브랜치 생성 → 3. 테스트 실행 → 4. PR 생성

## 라이선스

[MIT](LICENSE)

---

이 프로젝트는 OWASP 재단 또는 NIST와 공식적으로 제휴하거나 보증받지 않았습니다.
