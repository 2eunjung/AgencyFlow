# AgencyFlow 데이터베이스 구조 및 주요 테이블 설계

> 문서 상태: 초안 v0.1 · 최종 수정일 : 2026-09-27
>
> 구현 확인 기준: `a0ebeb0`의 `sqlite_server.py` DDL·저장 함수 및 `static/project.js` 데이터 구조
>
> 이 문서는 현재 구현된 구조를 설명한다. 향후 정규화 후보를 실제 존재하는 테이블과 혼동하지 않는다.

## 1. 저장 구조 개요

| 항목 | 현재 구조 |
|---|---|
| DBMS | SQLite, Python 표준 `sqlite3` 사용 |
| DB 파일 | 애플리케이션 폴더의 `projects.sqlite3` |
| 비밀키 파일 | 같은 폴더의 `projects.secret` |
| 초기화·기존 구조 보완 | `sqlite_server.py`의 `ensure_db()` |
| 로컬·배포 연결 | 로컬 HTTP 서버와 `wsgi.py`가 동일한 서버·DB 처리 코드 사용 |
| 데이터 구분 | 프로젝트 테이블에 `public`/`private` 모드 컬럼 유지. 비로그인 공개 응답은 현재 빈 샘플 목록 |
| 저장 방식 | 회원·연차·로그는 개별 행, 프로젝트 하위 정보와 자료실은 JSON 병행 |

프로젝트는 목록용 필드를 별도 컬럼으로 두고 전체 내용을 `data_json`에 저장한다. 일정·이슈·소통내역·완료 이력을 별도 관계형 테이블로 분리한 구조는 아니다. 자료실도 게시글·댓글·첨부파일을 `app_state`의 한 JSON 배열로 저장한다.

## 2. 실제 테이블 목록

SQLite 내부 관리 테이블을 제외하면 초기화 코드에서 정의하는 업무·호환 테이블은 12개이다.

| 테이블 | 역할 | 식별 기준 |
|---|---|---|
| `project_records` | 현재 프로젝트 본문과 목록용 필드 | `(mode, id)` 복합 PK |
| `admin_project_records` | 관리자 보조 프로젝트 데이터 | `(mode, id)` 복합 PK |
| `users_secure` | 회원, 로그인 자격, 역할·부서·직책 | `id_lookup` PK |
| `departments` | 부서명과 표시 색상 | `id` PK, `name` UNIQUE |
| `login_lockouts` | 계정별 로그인 실패·잠금 | `id_lookup` PK |
| `login_logs` | 로그인 성공·실패 이력 | `id` PK |
| `project_logs` | 프로젝트 변경·업무 처리 이력 | `id` PK |
| `leave_balances` | 사용자·연도별 연차 총량과 잔여량 | `id` PK, `(user_id_lookup, year)` UNIQUE |
| `leave_requests` | 연차 신청·승인·반려 이력 | `id` PK |
| `company_holidays` | 회사 휴일·일정 | `id` PK, `(date, title)` UNIQUE |
| `app_state` | 키별 애플리케이션 데이터, 자료실 JSON | `key` PK |
| `datasets` | 기존 프로젝트 일괄 JSON의 호환·이관용 저장소 | `mode` PK |

## 3. 테이블별 주요 컬럼

아래는 신규 DB 생성 기준이다. `INTEGER PK AUTOINCREMENT`는 증가형 기본키를 뜻한다. JSON은 SQLite의 별도 JSON 타입이 아닌 `TEXT`로 저장한다.

### 3.1 `project_records`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `mode` | TEXT NOT NULL, `public`/`private` CHECK | 데이터 모드 |
| `id` | TEXT NOT NULL | 프로젝트 내부 식별자 |
| `project_no` | TEXT | 화면의 PJ No. 앞자리 0을 보존 |
| `name` | TEXT | 프로젝트명 |
| `status` | TEXT | 작업상태 |
| `milestone` | TEXT | 마일스톤 |
| `pm` | TEXT | PM 이름 |
| `data_json` | TEXT NOT NULL | 전체 프로젝트 객체 |
| `created_at`, `updated_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 행 생성·갱신 시각 |

기본키는 `(mode, id)`이다. `project_no`에는 DB UNIQUE 제약이 없다. 화면의 PJ No와 내부 `id`를 동일한 식별자로 간주하지 않는다.

JSON과 목록용 컬럼은 `insert_projects()`에서 함께 작성한다. 실제 읽기는 `data_json`을 복원하는 방식이므로 컬럼만 수동으로 수정하면 JSON과 값이 어긋날 수 있다.

### 3.2 `admin_project_records`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `mode`, `id` | TEXT NOT NULL, 복합 PK | 모드 및 식별자. mode CHECK는 프로젝트 테이블과 동일 |
| `project_no`, `name` | TEXT | PJ No와 프로젝트명 |
| `progress_status`, `milestone`, `pm` | TEXT | 보조 진행상태·마일스톤·PM |
| `data_json` | TEXT NOT NULL | 관리자 보조 프로젝트 객체 |
| `created_at`, `updated_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 행 시각 |

스냅샷의 `adminProjects`는 관리자에게만 반환한다. 일반 프로젝트와 물리적인 FK로 묶여 있지 않으며 기존 데이터의 보조 필드를 함께 활용하는 구조이다.

### 3.3 `users_secure`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id_lookup` | TEXT PK | 정규화한 로그인 ID의 키 기반 HMAC 조회값 |
| `id_enc`, `name_enc` | TEXT NOT NULL | 암호화한 로그인 ID·이름 |
| `password` | TEXT NOT NULL | 소금값을 포함한 PBKDF2 해시 문자열 |
| `role` | TEXT NOT NULL, CHECK | `admin`, `team_lead`, `user` |
| `approval_status` | TEXT NOT NULL | 활성화·비활성화 상태 |
| `department`, `position` | TEXT NOT NULL, 기본값 빈 문자열 | 부서·직책 |
| `hire_date`, `resign_date` | TEXT NOT NULL, 기본값 빈 문자열 | 입사일·퇴사일 |
| `created_at`, `updated_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 회원 행 시각 |

PM은 `role`의 별도 값이 아니라 `department=pm`으로 판단한다. 부서명은 문자열로 저장되며 `departments.id`를 참조하는 외래키는 없다.

### 3.4 `departments`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 부서 식별자 |
| `name` | TEXT NOT NULL UNIQUE | 부서명 |
| `color` | TEXT NOT NULL, 기본값 `#d9eadf` | 화면의 부서 색상 |
| `created_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 생성 시각 |

기본 부서는 경영관리, 영업, pm, 디자인, 퍼블리싱, 프로그램, 유지보수이다. 부서명 변경에 따른 사용자 정보 변경은 애플리케이션에서 처리한다.

### 3.5 `login_lockouts`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id_lookup` | TEXT PK | 로그인 시도 계정의 조회값 |
| `failure_count` | INTEGER NOT NULL, 기본값 0 | 누적 실패 횟수 |
| `locked` | INTEGER NOT NULL, 기본값 0 | 잠금 여부, 0/1 사용 |
| `updated_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 마지막 갱신 시각 |

실패 횟수 5회 이상이면 잠금 상태로 판단한다. 존재하지 않는 ID의 실패도 기록할 수 있으므로 모든 행이 반드시 `users_secure`에 대응하지는 않는다. 성공 로그인 또는 관리자 비밀번호 재설정 시 해당 행을 제거한다. 잠긴 계정은 성공 로그인 경로에 진입하지 못하므로 관리자 재설정이 필요하다.

### 3.6 `login_logs`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 로그 ID |
| `user_id_enc`, `name_enc` | TEXT NOT NULL | 로그인 ID·이름의 암호문 |
| `role` | TEXT NOT NULL | 시도 계정의 역할 |
| `result` | TEXT NOT NULL, `success`/`failure` CHECK | 결과 |
| `failure_reason`, `ip` | TEXT NOT NULL | 실패 사유, 접속 IP |
| `created_at` | TEXT NOT NULL | 기록 시각 |

조회 함수는 최근 1,000건을 반환한다. 이 조회 제한이 오래된 로그의 자동 삭제 정책을 뜻하지는 않는다.

### 3.7 `project_logs`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 로그 ID |
| `user_id_enc`, `name_enc`, `role` | TEXT NOT NULL | 처리자 ID·이름의 암호문과 역할 |
| `action`, `category` | TEXT NOT NULL | 작업 종류와 업무 구분 |
| `project_no` | TEXT NOT NULL | 대상 PJ No |
| `project_name_enc` | TEXT NOT NULL | 대상 프로젝트명의 암호문 |
| `target`, `summary_enc` | TEXT NOT NULL | 변경 대상과 암호화한 변경 요약 |
| `created_at` | TEXT NOT NULL | 처리 시각 |

프로젝트 저장 전후 비교와 승인·반려 처리에서 서버가 기록한다. 페이지 크기는 기본 10건, 최대 100건이다. 로그에는 프로젝트 FK가 없어 프로젝트 삭제와 자동 연쇄 삭제되지 않는다.

### 3.8 `leave_balances`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 연차 잔액 행 ID |
| `user_id_lookup` | TEXT NOT NULL | 사용자 조회값 |
| `user_id_enc`, `user_name_enc` | TEXT NOT NULL | 사용자 ID·이름 암호문 |
| `year` | INTEGER NOT NULL | 기준 연도 |
| `total_days` | REAL NOT NULL, DB 기본값 15 | 부여 연차. 생성 함수는 계산한 값을 명시적으로 저장 |
| `remaining_days` | REAL, NULL 허용 | 저장된 잔여 연차 또는 미지정 |
| `created_at`, `updated_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 행 시각 |

`(user_id_lookup, year)`는 UNIQUE이다. `remaining_days`가 NULL이면 총량에서 승인 사용량을 차감해 표시하고, 저장값이 있으면 그 값을 사용한다. 부여값 산정과 관리자 조정 규칙은 [Requirements.md](Requirements.md)에 기술한다.

### 3.9 `leave_requests`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 신청 ID |
| `user_id_lookup` | TEXT NOT NULL | 신청 대상 사용자 조회값 |
| `user_id_enc`, `user_name_enc` | TEXT NOT NULL | 대상 ID·이름 암호문 |
| `year` | INTEGER NOT NULL | 시작일 기준 연도 |
| `start_date`, `end_date` | TEXT NOT NULL | 시작일·종료일 |
| `days` | REAL NOT NULL | 신청 일수 |
| `leave_type`, `reason_enc` | TEXT NOT NULL | 휴가 유형, 암호화한 사유 |
| `status` | TEXT NOT NULL, CHECK | `pending`, `approved`, `rejected` |
| `approved_by_enc`, `approved_at` | TEXT NOT NULL, 기본값 빈 문자열 | 승인 처리자와 처리 시각 |
| `created_at`, `updated_at` | TEXT NOT NULL | 신청·갱신 시각 |

승인 상태 변경 및 승인된 휴가 수정·삭제에 따라 잔여 일수를 다시 계산한다. 날짜와 신청 일수의 세부 유효성은 DB CHECK가 아니라 서버 함수에서 검사한다.

### 3.10 `company_holidays`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 휴일 ID |
| `date`, `title` | TEXT NOT NULL | 날짜와 일정명, 두 컬럼의 조합 UNIQUE |
| `kind` | TEXT NOT NULL, 기본값 `회사휴일` | 휴일·일정 구분 |
| `created_by_enc` | TEXT NOT NULL, 기본값 빈 문자열 | 등록자 암호문 |
| `created_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 등록 시각 |

### 3.11 `app_state`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `key` | TEXT PK | 데이터 구분 키 |
| `value` | TEXT NOT NULL | JSON 직렬화 문자열 |

현재 자료실은 `key=project_library_posts`의 게시글 배열에 저장한다. `mode` 컬럼이 없어 공개·비공개 모드별 별도 자료실 테이블은 아니다. 비로그인 응답과 자료실 접근은 서버에서 제어한다.

### 3.12 `datasets`

| 컬럼 | 타입·제약 | 설명 |
|---|---|---|
| `mode` | TEXT PK, `public`/`private` CHECK | 데이터 모드 |
| `projects_json`, `admin_projects_json` | TEXT NOT NULL | 이전 방식의 일괄 프로젝트 JSON |
| `updated_at` | TEXT NOT NULL, 기본값 CURRENT_TIMESTAMP | 저장 시각 |

현재 프로젝트 CRUD의 주 저장소는 `project_records`이다. `datasets`는 기존 데이터 이관을 위한 호환 구조이며, 프로젝트 테이블이 비었을 때 초기화 코드가 참조할 수 있다. 이 테이블을 최신 프로젝트의 자동 백업으로 간주하지 않는다.

## 4. JSON 내부 데이터 구조

### 4.1 프로젝트 객체

```text
project_records.data_json
├─ 기본·계약 정보: id, projectNo, name, contractDate, dueDate, openDate
├─ 금액·수금: contractAmount, balance, depositDate, monthlyCollection
├─ 분류·표시: milestone, status, hasIssue, isUrgent, hostingType 등
├─ 담당자: pm/designer/publisher/programmer, 각 Id 및 AssignedAt
├─ 연결: shortcutUrl, intranetUrl, designUrl
├─ 견적서: quoteFileName, quoteFileData
├─ clientContacts[]: 고객 담당자 이름·전화·이메일
├─ issues[]: 주요 이슈사항
├─ communications[]: 소통내역
├─ schedules[]: 일정과 일정별 history[]
└─ completionFlow: completed[], history[], hideApproval, pendingType
```

| 객체 | 주요 필드 |
|---|---|
| `issues[]` | `id`, `status`, `type`, `memo`, `date`, `createdAt`, `createdById`, `createdByName`, `visibility`, `resolved` |
| `communications[]` | `id`, `date`, `memo`, `createdAt`, `createdById`, `createdByName` |
| `schedules[]` | `id`, `date`, `projectId`, `projectNo`, `projectName`, `milestone`, `detail`, `staffRole`, `staffName`, `createdById`, `createdByName`, `createdAt`, `completed`, `note`, `history` |
| `schedules[].history[]` | `id`, `action`, `detail`, `scheduleDate`, `scheduleDetail`, `actorId`, `actorName`, `at` |
| `completionFlow.completed[]` | `design_worker`, `design_lead`, `design_pm` 등 완료된 공정 단계 키 |
| `completionFlow.history[]` | 처리 ID, `stage`, `label`, `userId`, `userName`, `at`, `action`, `memo`, `reason`, `completionType` 등 |

금액 입력은 화면 기준 만원·부가세 포함 단위를 사용한다. 일정·이슈 등의 존재 여부와 하위 필드는 기존 데이터에 따라 달라질 수 있으며, 화면 정규화 함수가 기본값을 보완한다.

### 4.2 자료실 게시글 배열

```text
app_state["project_library_posts"]
└─ 게시글[]
   ├─ id, projectId, projectNo, projectName
   ├─ important, title, content, url, messengerUrl
   ├─ createdById, createdByName, createdAt, updatedAt
   ├─ attachments[]: id, name, type, size, dataUrl
   └─ comments[]: id, content, createdById, createdByName, createdAt
```

첨부파일은 외부 파일 경로가 아니라 Base64 Data URL로 JSON에 들어간다. 견적서의 `quoteFileData`도 같은 저장 형태이다. 별도의 `uploads/` 저장소나 첨부파일 테이블은 현재 없다.

배열 전체를 갱신하는 방식이므로 게시글·댓글·파일 수가 늘면 DB 크기와 응답·저장 비용이 함께 늘어난다. 자료실 파일의 현재 한도는 게시글당 3개, 파일당 5 MiB이다.

## 5. 관계와 무결성

아래 관계는 애플리케이션의 논리적 연결이다. 현재 DDL에는 명시적인 `FOREIGN KEY`가 없다. 연결에서 `PRAGMA foreign_keys=ON`을 사용하더라도 선언되지 않은 관계까지 강제하지는 않는다.

| 연결 | 방식 | 주의점 |
|---|---|---|
| 사용자 ↔ 로그인 잠금 | `id_lookup` 비교 | 미등록 ID의 잠금 기록도 가능 |
| 사용자 ↔ 연차 | `id_lookup` ↔ `user_id_lookup` | DB 차원의 사용자 연쇄 삭제 없음 |
| 사용자 ↔ 부서 | 부서명 문자열 비교 | 정수 부서 ID 기반 FK가 아님 |
| 사용자 ↔ 프로젝트 배정 | JSON의 각 담당자 ID·이름 | 기존 데이터는 이름 매칭도 사용 |
| 프로젝트 ↔ 일정·이슈·승인 | 동일 프로젝트 JSON 내부 포함 | 독립 테이블의 FK 관계가 아님 |
| 프로젝트 ↔ 자료실 | 게시글의 `projectId`·`projectNo` | 프로젝트명도 게시 시점 값으로 저장; 자동 동기화·연쇄 삭제 없음 |
| 프로젝트 ↔ 변경 로그 | PJ No 및 대상 이름 스냅샷 | 프로젝트 삭제 후에도 로그가 남을 수 있음 |

고유성은 프로젝트의 `(mode, id)`, 회원의 `id_lookup`, 부서명, 사용자·연도별 잔액, 휴일의 날짜·제목 조합에서 보장한다. 사용자명·PJ No 전체의 고유성은 이 제약과 구분한다.

## 6. 주요 인덱스

| 테이블 | 인덱스 대상 |
|---|---|
| `project_records` | `(mode, project_no)`, `(mode, status)`, `(mode, milestone)` |
| `admin_project_records` | `(mode, project_no)` |
| `login_logs` | `created_at DESC`, `result` |
| `project_logs` | `created_at DESC`, `project_no` |
| `leave_balances` | `(user_id_lookup, year)` |
| `leave_requests` | `(user_id_lookup, year)`, `status`, `start_date DESC` |

PK·UNIQUE에 따른 SQLite 내부 인덱스는 별도이다. 일부 목록 검색·집계는 전체 JSON을 읽은 뒤 Python 또는 브라우저에서 처리하므로 모든 화면 필터가 SQL 인덱스를 사용하는 것은 아니다.

## 7. 저장·초기화·시간 처리

- 프로젝트 저장은 현재 목록과 수신 목록을 권한에 맞게 병합한 뒤 해당 모드 행들을 삭제·재삽입하는 경로를 사용한다. 배정·공정 승인도 전체 목록을 재작성하는 경로가 있다.
- 변경 로그 함수에도 커밋이 있으므로 개별 저장 흐름의 트랜잭션 범위는 호출 경로별로 확인해야 한다.
- 행의 `created_at`은 삭제·재삽입 시 다시 설정될 수 있다. 프로젝트의 최초 업무 발생일이나 감사용 불변 시각으로 사용하지 않는다.
- 자료실은 `app_state`의 게시글 배열 전체를 갱신한다. 프로젝트와 자료실 모두 사용자 간 저장 충돌을 검사하는 버전 필드가 없다.
- `ensure_db()`는 테이블·인덱스 생성과 일부 컬럼 추가, 기존 역할 제약의 보완, 구 데이터 이관을 수행한다. 별도 스키마 버전 관리 도구는 없다.
- 날짜는 주로 `YYYY-MM-DD` 문자열이다. 시각은 SQLite `CURRENT_TIMESTAMP`, 서버 현지 시각 문자열, 브라우저 ISO 문자열이 혼재한다. DB에 단일 시간대 정책이 강제되어 있지 않다.

## 8. 인증 데이터와 백업

- 비밀번호는 PBKDF2-HMAC-SHA256, 260,000회 반복과 무작위 소금값을 사용해 해시로 저장한다.
- 로그인 ID 조회값은 소문자·공백 정리 후 키 기반 HMAC으로 생성한다.
- `*_enc`는 `projects.secret`에서 파생한 키를 사용하는 현재 애플리케이션의 `enc:v1:` 암호화 형식이다. 이 문서는 이를 외부 표준 암호화 제품 또는 검증 완료 암호 모듈로 표현하지 않는다.
- 프로젝트 JSON, 자료실 JSON, 고객 연락처·담당자명 등이 모두 암호화되는 것은 아니다. DB 전체 암호화가 적용된 구조도 아니다.
- 로그인 세션은 DB 테이블이 아니라 프로세스 메모리의 `SESSIONS`에 저장한다. 서버 재시작 시 사라지고 여러 작업 프로세스 간 자동 공유되지 않는다.
- `projects.sqlite3`와 `projects.secret`은 반드시 같은 환경의 한 쌍으로 백업·복원한다. 비밀키가 다르면 암호화 필드 복호화와 ID 조회가 실패할 수 있다.
- 실행 중인 DB의 백업은 SQLite 백업 기능을 사용하거나 쓰기가 중지된 상태에서 수행한다. 두 파일, 백업, 환경변수 파일을 공개 Git 저장소나 정적 파일 경로에 두지 않는다.
- 로컬 더미 데이터는 DB에 포함되며 Git Push로 배포 환경에 자동 반영되지 않는다.

## 9. 후속 설계 후보

현재 존재하는 테이블이 아니라 필요 시 검토할 구조이다.

| 개선 후보 | 목적 |
|---|---|
| 프로젝트별 `version`과 부분 갱신 | 오래된 화면의 저장이 다른 사용자의 변경을 덮어쓰는 문제 방지 |
| 일정·이슈·승인 이력의 독립 테이블 | 개별 수정, 검색, 집계, 이력 보존 단위 개선 |
| 자료실 게시글·댓글·첨부 메타데이터 분리 | 배열 전체 재작성 감소, 프로젝트별 접근 제어 용이화 |
| 첨부파일의 별도 비공개 저장소 | JSON·DB 용량 및 목록 응답 크기 감소 |
| 사용자·부서·배정의 명시적인 참조 관계 | 이름 변경·동명이인·삭제 시 일관성 개선 |
| 공유 세션 저장소와 마이그레이션 버전 | 여러 프로세스 운영 및 배포 변경 관리 |

Requirements.md와 Roadmap.md에 기재된 후속 계획 중 데이터 저장 구조와 직접 관련된 설계 후보만 이 절에 정리한다. 업무 정책과 화면 기능에 대한 개선 계획은 Requirements.md와 Roadmap.md를 참고한다
