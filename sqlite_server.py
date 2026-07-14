import base64
import hashlib
import hmac
import secrets
import time
import json
import os
import re
import sqlite3
from datetime import date, datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "projects.sqlite3"
SECRET_PATH = BASE_DIR / "projects.secret"
DEFAULT_ADMIN_ID = "admin"
DEFAULT_ADMIN_PASSWORD = os.environ.get("AGENCY_FLOW_ADMIN_PASSWORD", "").strip()
PASSWORD_ITERATIONS = 260000
PASSWORD_HASH_PREFIX = f"pbkdf2:{PASSWORD_ITERATIONS}:"
VALID_MODES = {"public", "private"}
MAX_JSON_BODY_BYTES = 25 * 1024 * 1024
MAX_PDF_BYTES = 10 * 1024 * 1024
SESSION_TTL_SECONDS = 60 * 60
SESSION_TOKEN_BYTES = 32
LOGIN_FAILURE_LIMIT = 5
SESSIONS = {}
LOGIN_FAILURE_COUNT = 0
LOGIN_LOCKED = False
DEFAULT_DEPARTMENTS = ("경영관리", "영업", "pm", "디자인", "퍼블리싱", "프로그램", "유지보수")
PDF_DANGEROUS_MARKERS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/XFA",
)

SAMPLE_PROJECTS = [{'id': 'sample-001', 'no': 1, 'projectNo': 'S-1001', 'name': '샘플 기업 홈페이지 구축', 'industry': '제조', 'contractDate': '2026-01-06', 'dueDate': '2026-02-11', 'openDate': '', 'contractAmount': 3200, 'balance': 800, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '자료요청중', 'adminMilestone': '자료요청중', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM', 'designer': '디자이너A', 'publisher': '퍼블리셔A', 'programmer': '개발자A', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': True, 'hasIssue': True, 'issues': [{'id': 'sample-issue-001', 'memo': '샘플 확인 사항입니다.', 'createdAt': '2026-01-08T09:00:00'}], 'clientContacts': [{'id': 'sample-contact-001', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-001', 'date': '2026-01-09', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-002', 'no': 2, 'projectNo': 'S-1002', 'name': '샘플 브랜드 랜딩페이지', 'industry': '서비스', 'contractDate': '2026-02-07', 'dueDate': '2026-03-12', 'openDate': '', 'contractAmount': 1200, 'balance': 1200, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '화면설계중', 'adminMilestone': '화면설계중', 'status': '피드백대기', 'progressStatus': '피드백대기', 'pm': '샘플PM', 'designer': '디자이너B', 'publisher': '퍼블리셔B', 'programmer': '', 'hostingType': '일반 호스팅', 'hasLanding': True, 'hasForeignLanguage': False, 'monthlyCollection': True, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-002', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-002', 'date': '2026-02-10', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-003', 'no': 3, 'projectNo': 'S-1003', 'name': '샘플 다국어 사이트 개편', 'industry': '교육', 'contractDate': '2026-03-08', 'dueDate': '2026-04-13', 'openDate': '', 'contractAmount': 5400, 'balance': 2700, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '메인시안중', 'adminMilestone': '메인시안중', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM2', 'designer': '디자이너C', 'publisher': '퍼블리셔C', 'programmer': '개발자C', 'hostingType': '단독서버', 'hasLanding': False, 'hasForeignLanguage': True, 'monthlyCollection': True, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-003', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-003', 'date': '2026-03-11', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-004', 'no': 4, 'projectNo': 'S-1004', 'name': '샘플 쇼핑몰 리뉴얼', 'industry': '유통', 'contractDate': '2026-04-09', 'dueDate': '2026-05-14', 'openDate': '', 'contractAmount': 4100, 'balance': 1300, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '서브시안중', 'adminMilestone': '서브시안중', 'status': '고객지연', 'progressStatus': '고객지연', 'pm': '샘플PM2', 'designer': '디자이너D', 'publisher': '퍼블리셔A', 'programmer': '개발자B', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': True, 'hasIssue': True, 'issues': [{'id': 'sample-issue-004', 'memo': '샘플 확인 사항입니다.', 'createdAt': '2026-04-11T09:00:00'}], 'clientContacts': [{'id': 'sample-contact-004', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-004', 'date': '2026-04-12', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-005', 'no': 5, 'projectNo': 'S-1005', 'name': '샘플 병원 사이트 제작', 'industry': '의료', 'contractDate': '2026-05-10', 'dueDate': '2026-06-15', 'openDate': '', 'contractAmount': 2800, 'balance': 500, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '상세디자인', 'adminMilestone': '상세디자인', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM2', 'designer': '디자이너E', 'publisher': '퍼블리셔B', 'programmer': '개발자C', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': True, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-005', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-005', 'date': '2026-05-13', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-006', 'no': 6, 'projectNo': 'S-1006', 'name': '샘플 채용 캠페인 페이지', 'industry': '인사', 'contractDate': '2026-01-11', 'dueDate': '2026-02-16', 'openDate': '', 'contractAmount': 900, 'balance': 900, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '퍼블리싱중', 'adminMilestone': '퍼블리싱중', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM', 'designer': '디자이너F', 'publisher': '퍼블리셔C', 'programmer': '', 'hostingType': '일반 호스팅', 'hasLanding': True, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-006', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-006', 'date': '2026-01-14', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-007', 'no': 7, 'projectNo': 'S-1007', 'name': '샘플 예약 시스템 구축', 'industry': '서비스', 'contractDate': '2026-02-12', 'dueDate': '2026-03-17', 'openDate': '', 'contractAmount': 6200, 'balance': 3100, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '프로그램중', 'adminMilestone': '프로그램중', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM2', 'designer': '디자이너A', 'publisher': '퍼블리셔D', 'programmer': '개발자D', 'hostingType': '단독서버', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-007', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-007', 'date': '2026-02-15', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-008', 'no': 8, 'projectNo': 'S-1008', 'name': '샘플 제품 소개 사이트', 'industry': '제조', 'contractDate': '2026-03-13', 'dueDate': '2026-04-18', 'openDate': '', 'contractAmount': 2300, 'balance': 0, 'depositDate': '2026-03-14', 'shortcutUrl': '', 'designUrl': '', 'milestone': '고객검수중', 'adminMilestone': '고객검수중', 'status': '피드백대기', 'progressStatus': '피드백대기', 'pm': '샘플PM2', 'designer': '디자이너B', 'publisher': '퍼블리셔A', 'programmer': '개발자A', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': True, 'issues': [{'id': 'sample-issue-008', 'memo': '샘플 확인 사항입니다.', 'createdAt': '2026-03-15T09:00:00'}], 'clientContacts': [{'id': 'sample-contact-008', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-008', 'date': '2026-03-16', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-009', 'no': 9, 'projectNo': 'S-1009', 'name': '샘플 학원 홈페이지', 'industry': '교육', 'contractDate': '2026-04-14', 'dueDate': '2026-05-19', 'openDate': '', 'contractAmount': 1800, 'balance': 0, 'depositDate': '2026-04-15', 'shortcutUrl': '', 'designUrl': '', 'milestone': '오픈안내함', 'adminMilestone': '오픈안내함', 'status': '오픈대기', 'progressStatus': '오픈대기', 'pm': '샘플PM', 'designer': '디자이너C', 'publisher': '퍼블리셔B', 'programmer': '개발자B', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-009', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-009', 'date': '2026-04-17', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-010', 'no': 10, 'projectNo': 'S-1010', 'name': '샘플 글로벌 홍보 사이트', 'industry': '무역', 'contractDate': '2026-05-15', 'dueDate': '2026-06-20', 'openDate': '', 'contractAmount': 3500, 'balance': 1700, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '외국어작업', 'adminMilestone': '외국어작업', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM2', 'designer': '디자이너D', 'publisher': '퍼블리셔C', 'programmer': '개발자C', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': True, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-010', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-010', 'date': '2026-05-18', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-011', 'no': 11, 'projectNo': 'S-1011', 'name': '샘플 내부 포털', 'industry': 'IT', 'contractDate': '2026-01-16', 'dueDate': '2026-02-21', 'openDate': '', 'contractAmount': 4800, 'balance': 4800, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '작업중단-고객요청', 'adminMilestone': '작업중단-고객요청', 'status': '작업중단', 'progressStatus': '작업중단', 'pm': '샘플PM2', 'designer': '디자이너E', 'publisher': '퍼블리셔D', 'programmer': '개발자D', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-011', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-011', 'date': '2026-01-19', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-012', 'no': 12, 'projectNo': 'S-1012', 'name': '샘플 법무법인 사이트', 'industry': '법률', 'contractDate': '2026-02-17', 'dueDate': '2026-03-22', 'openDate': '', 'contractAmount': 2600, 'balance': 2600, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '내용증명', 'adminMilestone': '내용증명', 'status': '고객지연', 'progressStatus': '고객지연', 'pm': '샘플PM', 'designer': '디자이너F', 'publisher': '퍼블리셔A', 'programmer': '', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': True, 'issues': [{'id': 'sample-issue-012', 'memo': '샘플 확인 사항입니다.', 'createdAt': '2026-02-19T09:00:00'}], 'clientContacts': [{'id': 'sample-contact-012', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-012', 'date': '2026-02-20', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-013', 'no': 13, 'projectNo': 'S-1013', 'name': '샘플 계약 분쟁 프로젝트', 'industry': '기타', 'contractDate': '2026-03-18', 'dueDate': '2026-04-23', 'openDate': '', 'contractAmount': 3900, 'balance': 3900, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '법정다툼', 'adminMilestone': '법정다툼', 'status': '작업중단', 'progressStatus': '작업중단', 'pm': '샘플PM2', 'designer': '디자이너A', 'publisher': '퍼블리셔B', 'programmer': '개발자A', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-013', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-013', 'date': '2026-03-21', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-014', 'no': 14, 'projectNo': 'S-1014', 'name': '샘플 이벤트 페이지', 'industry': '마케팅', 'contractDate': '2026-04-19', 'dueDate': '2026-05-24', 'openDate': '2026-06-01', 'contractAmount': 700, 'balance': 0, 'depositDate': '2026-04-20', 'shortcutUrl': '', 'designUrl': '', 'milestone': '프로젝트종료', 'adminMilestone': '프로젝트종료', 'status': '완료', 'progressStatus': '완료', 'pm': '샘플PM', 'designer': '디자이너B', 'publisher': '퍼블리셔C', 'programmer': '', 'hostingType': '일반 호스팅', 'hasLanding': True, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-014', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-014', 'date': '2026-04-22', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-015', 'no': 15, 'projectNo': 'S-1015', 'name': '샘플 협회 홈페이지', 'industry': '공공', 'contractDate': '2026-05-20', 'dueDate': '2026-06-25', 'openDate': '2026-07-01', 'contractAmount': 3300, 'balance': 0, 'depositDate': '2026-05-21', 'shortcutUrl': '', 'designUrl': '', 'milestone': '프로젝트종료', 'adminMilestone': '프로젝트종료', 'status': '완료', 'progressStatus': '완료', 'pm': '샘플PM2', 'designer': '디자이너C', 'publisher': '퍼블리셔D', 'programmer': '개발자B', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-015', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-015', 'date': '2026-05-23', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-016', 'no': 16, 'projectNo': 'S-1016', 'name': '샘플 프랜차이즈 사이트', 'industry': '외식', 'contractDate': '2026-01-21', 'dueDate': '2026-02-26', 'openDate': '', 'contractAmount': 2900, 'balance': 2900, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '자료요청중', 'adminMilestone': '자료요청중', 'status': '입금대기', 'progressStatus': '입금대기', 'pm': '샘플PM2', 'designer': '디자이너D', 'publisher': '퍼블리셔A', 'programmer': '개발자C', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-016', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-016', 'date': '2026-01-24', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-017', 'no': 17, 'projectNo': 'S-1017', 'name': '샘플 SaaS 소개 페이지', 'industry': 'IT', 'contractDate': '2026-02-22', 'dueDate': '2026-03-27', 'openDate': '', 'contractAmount': 1600, 'balance': 800, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '화면설계중', 'adminMilestone': '화면설계중', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM', 'designer': '디자이너E', 'publisher': '퍼블리셔B', 'programmer': '개발자D', 'hostingType': '일반 호스팅', 'hasLanding': True, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-017', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-017', 'date': '2026-02-25', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-018', 'no': 18, 'projectNo': 'S-1018', 'name': '샘플 금융 서비스 사이트', 'industry': '금융', 'contractDate': '2026-03-23', 'dueDate': '2026-04-28', 'openDate': '', 'contractAmount': 5100, 'balance': 2500, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '상세디자인', 'adminMilestone': '상세디자인', 'status': '피드백대기', 'progressStatus': '피드백대기', 'pm': '샘플PM2', 'designer': '디자이너F', 'publisher': '퍼블리셔C', 'programmer': '개발자A', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-018', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-018', 'date': '2026-03-26', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-019', 'no': 19, 'projectNo': 'S-1019', 'name': '샘플 문화재단 사이트', 'industry': '문화', 'contractDate': '2026-04-24', 'dueDate': '2026-05-28', 'openDate': '', 'contractAmount': 2400, 'balance': 1200, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '퍼블리싱중', 'adminMilestone': '퍼블리싱중', 'status': '진행중', 'progressStatus': '진행중', 'pm': '샘플PM2', 'designer': '디자이너A', 'publisher': '퍼블리셔D', 'programmer': '', 'hostingType': '일반 호스팅', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': False, 'issues': [], 'clientContacts': [{'id': 'sample-contact-019', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-019', 'date': '2026-04-27', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}, {'id': 'sample-020', 'no': 20, 'projectNo': 'S-1020', 'name': '샘플 물류 플랫폼', 'industry': '물류', 'contractDate': '2026-05-25', 'dueDate': '2026-06-28', 'openDate': '', 'contractAmount': 7600, 'balance': 5600, 'depositDate': '', 'shortcutUrl': '', 'designUrl': '', 'milestone': '프로그램중', 'adminMilestone': '프로그램중', 'status': '입금지연', 'progressStatus': '입금지연', 'pm': '샘플PM', 'designer': '디자이너B', 'publisher': '퍼블리셔A', 'programmer': '개발자B', 'hostingType': '단독서버', 'hasLanding': False, 'hasForeignLanguage': False, 'monthlyCollection': False, 'hasIssue': True, 'issues': [{'id': 'sample-issue-020', 'memo': '샘플 확인 사항입니다.', 'createdAt': '2026-05-27T09:00:00'}], 'clientContacts': [{'id': 'sample-contact-020', 'name': '샘플 담당자', 'department': '마케팅팀', 'phone': '010-0000-0000', 'email': 'sample@example.com', 'memo': ''}], 'communications': [{'id': 'sample-comm-020', 'date': '2026-05-28', 'memo': '샘플 커뮤니케이션 내역입니다.'}], 'quoteFileName': '', 'quoteFileData': ''}]


def load_secret():
    if SECRET_PATH.exists():
        return base64.b64decode(SECRET_PATH.read_text(encoding="ascii"))
    secret = os.urandom(32)
    SECRET_PATH.write_text(base64.b64encode(secret).decode("ascii"), encoding="ascii")
    return secret


APP_SECRET = load_secret()


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def normalize_mode(value):
    return "private" if value == "private" else "public"


def read_json_file(name, fallback):
    path = BASE_DIR / name
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(str(text).encode("ascii"))


def crypto_key(label):
    return hmac.new(APP_SECRET, label.encode("utf-8"), hashlib.sha256).digest()


def keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def encrypt_text(value):
    plain = str(value or "").encode("utf-8")
    nonce = os.urandom(16)
    key = crypto_key("identity-encryption")
    stream = keystream(key, nonce, len(plain))
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    tag = hmac.new(crypto_key("identity-auth"), nonce + cipher, hashlib.sha256).digest()
    return "enc:v1:" + b64(nonce + cipher + tag)


def decrypt_text(value):
    text = str(value or "")
    if not text.startswith("enc:v1:"):
        return text
    raw = unb64(text[len("enc:v1:"):])
    if len(raw) < 48:
        return ""
    nonce = raw[:16]
    tag = raw[-32:]
    cipher = raw[16:-32]
    expected = hmac.new(crypto_key("identity-auth"), nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Encrypted user data was modified.")
    stream = keystream(crypto_key("identity-encryption"), nonce, len(cipher))
    plain = bytes(a ^ b for a, b in zip(cipher, stream))
    return plain.decode("utf-8")


def id_lookup(user_id):
    normalized = str(user_id or "").strip().lower()
    return hmac.new(crypto_key("identity-lookup"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password, salt=None):
    salt_bytes = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt_bytes, PASSWORD_ITERATIONS)
    return f"{PASSWORD_HASH_PREFIX}{b64(salt_bytes)}:{b64(digest)}"


def verify_password(password, stored):
    value = str(stored or "")
    if not value.startswith("pbkdf2:"):
        return False
    try:
        prefix, rounds_text, body = value.split(":", 2)
        rounds = int(rounds_text)
        salt_part, hash_part = body.rsplit(":", 1)
        salt = unb64(salt_part)
        expected = unb64(hash_part)
        actual = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def password_needs_rehash(stored):
    return not str(stored or "").startswith(PASSWORD_HASH_PREFIX)


def normalize_approval_status(status, role="user"):
    if status in ("활성화", "승인", "劝己拳", "铰牢"):
        return "활성화"
    if status in ("비활성화", "대기", "거부", "厚劝己拳", "措扁", "芭何"):
        return "비활성화"
    return "활성화" if role == "admin" else "비활성화"



def public_user(row):
    return {
        "id": decrypt_text(row["id_enc"]),
        "name": decrypt_text(row["name_enc"]),
        "role": row["role"],
        "approvalStatus": row["approval_status"],
        "department": row["department"] if "department" in row.keys() else "",
    }


def normalize_department(value):
    department = str(value or "").strip()
    return department if department else DEFAULT_DEPARTMENTS[0]


def project_sort_key(project):
    value = project.get("projectNo") or project.get("no") or project.get("id") or ""
    text = str(value)
    return (0, int(text)) if text.isdigit() else (1, text)


def project_columns(project):
    return (
        str(project.get("id") or project.get("projectNo") or os.urandom(8).hex()),
        str(project.get("projectNo") or project.get("no") or ""),
        str(project.get("name") or ""),
        str(project.get("status") or project.get("progressStatus") or ""),
        str(project.get("milestone") or project.get("adminMilestone") or ""),
        str(project.get("pm") or ""),
        json.dumps(project, ensure_ascii=False),
    )


def admin_project_columns(project):
    return (
        str(project.get("projectNo") or project.get("id") or os.urandom(8).hex()),
        str(project.get("projectNo") or ""),
        str(project.get("name") or ""),
        str(project.get("progressStatus") or project.get("status") or ""),
        str(project.get("milestone") or ""),
        str(project.get("pm") or ""),
        json.dumps(project, ensure_ascii=False),
    )


def insert_projects(conn, mode, projects):
    conn.executemany(
        """
        INSERT INTO project_records
          (mode, id, project_no, name, status, milestone, pm, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mode, id) DO UPDATE SET
          project_no = excluded.project_no,
          name = excluded.name,
          status = excluded.status,
          milestone = excluded.milestone,
          pm = excluded.pm,
          data_json = excluded.data_json,
          updated_at = CURRENT_TIMESTAMP
        """,
        [(mode, *project_columns(project)) for project in projects],
    )


def insert_admin_projects(conn, mode, admin_projects):
    conn.executemany(
        """
        INSERT INTO admin_project_records
          (mode, id, project_no, name, progress_status, milestone, pm, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mode, id) DO UPDATE SET
          project_no = excluded.project_no,
          name = excluded.name,
          progress_status = excluded.progress_status,
          milestone = excluded.milestone,
          pm = excluded.pm,
          data_json = excluded.data_json,
          updated_at = CURRENT_TIMESTAMP
        """,
        [(mode, *admin_project_columns(project)) for project in admin_projects],
    )


def load_legacy_dataset(conn, mode):
    row = conn.execute(
        "SELECT projects_json, admin_projects_json FROM datasets WHERE mode = ?",
        (mode,),
    ).fetchone()
    if row:
        return {
            "projects": json.loads(row["projects_json"] or "[]"),
            "adminProjects": json.loads(row["admin_projects_json"] or "[]"),
        }
    filename = "projects-data.private.json" if mode == "private" else "projects-data.json"
    return read_json_file(filename, {"projects": [], "adminProjects": []})


def legacy_users(conn):
    table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    if not table:
        return []
    return conn.execute("SELECT id, password, name, role, approval_status FROM users").fetchall()


def upsert_secure_user(conn, user_id, password_hash, name, role, approval_status, department=""):
    role = "admin" if role == "admin" else "user"
    approval = normalize_approval_status(approval_status, role)
    department = normalize_department(department)
    conn.execute(
        """
        INSERT INTO users_secure
          (id_lookup, id_enc, password, name_enc, role, approval_status, department)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id_lookup) DO UPDATE SET
          id_enc = excluded.id_enc,
          password = excluded.password,
          name_enc = excluded.name_enc,
          role = excluded.role,
          approval_status = excluded.approval_status,
          department = excluded.department,
          updated_at = CURRENT_TIMESTAMP
        """,
        (id_lookup(user_id), encrypt_text(user_id), password_hash, encrypt_text(name), role, approval, department),
    )


def ensure_db():
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS datasets (
              mode TEXT PRIMARY KEY CHECK(mode IN ('public', 'private')),
              projects_json TEXT NOT NULL,
              admin_projects_json TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS project_records (
              mode TEXT NOT NULL CHECK(mode IN ('public', 'private')),
              id TEXT NOT NULL,
              project_no TEXT,
              name TEXT,
              status TEXT,
              milestone TEXT,
              pm TEXT,
              data_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (mode, id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_records_mode_project_no ON project_records(mode, project_no)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_records_mode_status ON project_records(mode, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_records_mode_milestone ON project_records(mode, milestone)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_project_records (
              mode TEXT NOT NULL CHECK(mode IN ('public', 'private')),
              id TEXT NOT NULL,
              project_no TEXT,
              name TEXT,
              progress_status TEXT,
              milestone TEXT,
              pm TEXT,
              data_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (mode, id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_project_records_mode_project_no ON admin_project_records(mode, project_no)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users_secure (
              id_lookup TEXT PRIMARY KEY,
              id_enc TEXT NOT NULL,
              password TEXT NOT NULL,
              name_enc TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
              approval_status TEXT NOT NULL,
              department TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(users_secure)").fetchall()]
        if "department" not in columns:
            conn.execute("ALTER TABLE users_secure ADD COLUMN department TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS departments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS company_holidays (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              date TEXT NOT NULL,
              title TEXT NOT NULL,
              created_by_enc TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(date, title)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_state (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_enc TEXT NOT NULL,
              name_enc TEXT NOT NULL,
              role TEXT NOT NULL,
              result TEXT NOT NULL CHECK(result IN ('success', 'failure')),
              failure_reason TEXT NOT NULL,
              ip TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_created_at ON login_logs(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_result ON login_logs(result)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS project_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_enc TEXT NOT NULL,
              name_enc TEXT NOT NULL,
              role TEXT NOT NULL,
              action TEXT NOT NULL,
              category TEXT NOT NULL,
              project_no TEXT NOT NULL,
              project_name_enc TEXT NOT NULL,
              target TEXT NOT NULL,
              summary_enc TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_logs_created_at ON project_logs(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_logs_project_no ON project_logs(project_no)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leave_balances (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_lookup TEXT NOT NULL,
              user_id_enc TEXT NOT NULL,
              user_name_enc TEXT NOT NULL,
              year INTEGER NOT NULL,
              total_days REAL NOT NULL DEFAULT 15,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(user_id_lookup, year)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_balances_user_year ON leave_balances(user_id_lookup, year)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leave_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_lookup TEXT NOT NULL,
              user_id_enc TEXT NOT NULL,
              user_name_enc TEXT NOT NULL,
              year INTEGER NOT NULL,
              start_date TEXT NOT NULL,
              end_date TEXT NOT NULL,
              days REAL NOT NULL,
              leave_type TEXT NOT NULL,
              reason_enc TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
              approved_by_enc TEXT NOT NULL DEFAULT '',
              approved_at TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_requests_user_year ON leave_requests(user_id_lookup, year)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_requests_status ON leave_requests(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_requests_start_date ON leave_requests(start_date DESC)")
        for department in DEFAULT_DEPARTMENTS:
            conn.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (department,))

        for mode in ("private",):
            count = conn.execute("SELECT COUNT(*) AS count FROM project_records WHERE mode = ?", (mode,)).fetchone()["count"]
            if count == 0:
                seed = load_legacy_dataset(conn, mode)
                insert_projects(conn, mode, seed.get("projects") or [])
                insert_admin_projects(conn, mode, seed.get("adminProjects") or [])

        secure_count = conn.execute("SELECT COUNT(*) AS count FROM users_secure").fetchone()["count"]
        if secure_count == 0:
            for row in legacy_users(conn):
                password = row["password"] if str(row["password"] or "").startswith("pbkdf2:") else hash_password(row["password"])
                upsert_secure_user(conn, row["id"], password, row["name"], row["role"], row["approval_status"])

        weak_rows = conn.execute("SELECT * FROM users_secure WHERE password NOT LIKE 'pbkdf2:%'").fetchall()
        for row in weak_rows:
            user = public_user(row)
            upsert_secure_user(conn, user["id"], hash_password(row["password"]), user.get("name", ""), user.get("role", "user"), user.get("approvalStatus", ""), user.get("department", ""))

        admin_row = conn.execute("SELECT 1 FROM users_secure WHERE id_lookup = ?", (id_lookup(DEFAULT_ADMIN_ID),)).fetchone()
        if not admin_row and DEFAULT_ADMIN_PASSWORD:
            upsert_secure_user(conn, DEFAULT_ADMIN_ID, hash_password(DEFAULT_ADMIN_PASSWORD), "관리자", "admin", "활성화", DEFAULT_DEPARTMENTS[0])

        legacy = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
        if legacy:
            conn.execute("DROP TABLE users")
        conn.commit()


def get_users(conn):
    rows = conn.execute("SELECT id_enc, name_enc, role, approval_status, department FROM users_secure ORDER BY role, id_lookup").fetchall()
    users = []
    year = date.today().year
    for row in rows:
        user = public_user(row)
        try:
            summary = leave_summary(conn, user, year)
        except Exception:
            summary = {"totalDays": 0, "remainingDays": 0}
        user["leaveTotalDays"] = summary.get("totalDays", 0)
        user["leaveRemainingDays"] = summary.get("remainingDays", 0)
        users.append(user)
    return users


def get_departments(conn):
    rows = conn.execute(
        """
        SELECT d.id, d.name, d.created_at, COUNT(u.id_lookup) AS user_count
        FROM departments d
        LEFT JOIN users_secure u ON u.department = d.name
        GROUP BY d.id, d.name, d.created_at
        ORDER BY d.id
        """
    ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "createdAt": row["created_at"],
            "userCount": row["user_count"],
        }
        for row in rows
    ]


def create_department(conn, name):
    department = str(name or "").strip()[:40]
    if not department:
        raise ValueError("Department name is required.")
    conn.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (department,))


def update_department(conn, department_id, name):
    department = str(name or "").strip()[:40]
    if not department:
        raise ValueError("Department name is required.")
    row = conn.execute("SELECT id, name FROM departments WHERE id = ?", (int(department_id),)).fetchone()
    if not row:
        raise ValueError("Department not found.")
    if conn.execute("SELECT 1 FROM departments WHERE name = ? AND id != ?", (department, int(department_id))).fetchone():
        raise ValueError("Department name already exists.")
    old_name = row["name"]
    conn.execute("UPDATE departments SET name = ? WHERE id = ?", (department, int(department_id)))
    conn.execute("UPDATE users_secure SET department = ? WHERE department = ?", (department, old_name))


def delete_department(conn, department_id):
    row = conn.execute(
        """
        SELECT d.id, d.name, COUNT(u.id_lookup) AS user_count
        FROM departments d
        LEFT JOIN users_secure u ON u.department = d.name
        WHERE d.id = ?
        GROUP BY d.id, d.name
        """,
        (int(department_id),),
    ).fetchone()
    if not row:
        raise ValueError("Department not found.")
    if int(row["user_count"] or 0) > 0:
        raise ValueError("Department has assigned members.")
    conn.execute("DELETE FROM departments WHERE id = ?", (int(department_id),))


def company_holidays(conn, year=None):
    params = []
    where = ""
    if year:
        where = "WHERE substr(date, 1, 4) = ?"
        params.append(str(year))
    rows = conn.execute(
        f"SELECT id, date, title, created_at FROM company_holidays {where} ORDER BY date DESC, id DESC",
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def create_company_holiday(conn, payload, user):
    holiday_date = str(payload.get("date") or "").strip()
    title = str(payload.get("title") or "").strip()[:80]
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", holiday_date):
        raise ValueError("Invalid holiday date.")
    if not title:
        raise ValueError("Holiday title is required.")
    conn.execute(
        "INSERT OR IGNORE INTO company_holidays (date, title, created_by_enc) VALUES (?, ?, ?)",
        (holiday_date, title, encrypt_text(user.get("id", ""))),
    )


def log_login_attempt(conn, user_id, name, role, result, failure_reason, ip):
    conn.execute(
        """
        INSERT INTO login_logs (user_id_enc, name_enc, role, result, failure_reason, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            encrypt_text(str(user_id or "")),
            encrypt_text(str(name or "")),
            "admin" if role == "admin" else "user",
            "success" if result == "success" else "failure",
            str(failure_reason or ""),
            str(ip or ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()


def login_logs(conn):
    rows = conn.execute(
        """
        SELECT id, user_id_enc, name_enc, role, result, failure_reason, ip, created_at
        FROM login_logs
        ORDER BY created_at DESC, id DESC
        LIMIT 1000
        """
    ).fetchall()
    return [
        {
            "id": row["id"],
            "userId": decrypt_text(row["user_id_enc"]) if row["user_id_enc"] else "",
            "name": decrypt_text(row["name_enc"]) if row["name_enc"] else "",
            "role": row["role"],
            "result": row["result"],
            "failureReason": row["failure_reason"],
            "ip": row["ip"],
            "createdAt": row["created_at"],
        }
        for row in rows
    ]


def leave_year(value=None):
    if value:
        text = str(value)
        if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
            return int(text[:4])
    return date.today().year


def leave_status_label(status):
    if status in ("approved", "승인"):
        return "승인"
    if status in ("rejected", "반려"):
        return "반려"
    return "대기"


def leave_status_code(status):
    if status in ("approved", "승인"):
        return "approved"
    if status in ("rejected", "반려"):
        return "rejected"
    return "pending"


def ensure_leave_balance(conn, user, year=None):
    year = int(year or date.today().year)
    lookup = id_lookup(user.get("id", ""))
    existing = conn.execute(
        "SELECT * FROM leave_balances WHERE user_id_lookup = ? AND year = ?",
        (lookup, year),
    ).fetchone()
    if existing:
        return existing
    conn.execute(
        """
        INSERT INTO leave_balances (user_id_lookup, user_id_enc, user_name_enc, year, total_days)
        VALUES (?, ?, ?, ?, ?)
        """,
        (lookup, encrypt_text(user.get("id", "")), encrypt_text(user.get("name", "")), year, 15.0),
    )
    return conn.execute(
        "SELECT * FROM leave_balances WHERE user_id_lookup = ? AND year = ?",
        (lookup, year),
    ).fetchone()


def leave_summary(conn, user, year=None):
    year = int(year or date.today().year)
    balance = ensure_leave_balance(conn, user, year)
    used_row = conn.execute(
        """
        SELECT COALESCE(SUM(days), 0) AS used_days
        FROM leave_requests
        WHERE user_id_lookup = ? AND year = ? AND status = 'approved'
        """,
        (id_lookup(user.get("id", "")), year),
    ).fetchone()
    total = float(balance["total_days"] or 0)
    used = float(used_row["used_days"] or 0)
    return {
        "year": year,
        "totalDays": total,
        "usedDays": used,
        "remainingDays": max(0, total - used),
    }


def leave_request_payload(row):
    return {
        "id": row["id"],
        "userId": decrypt_text(row["user_id_enc"]) if row["user_id_enc"] else "",
        "userName": decrypt_text(row["user_name_enc"]) if row["user_name_enc"] else "",
        "department": row["department"] if "department" in row.keys() else "",
        "year": row["year"],
        "startDate": row["start_date"],
        "endDate": row["end_date"],
        "days": float(row["days"] or 0),
        "type": row["leave_type"],
        "reason": decrypt_text(row["reason_enc"]) if row["reason_enc"] else "",
        "status": leave_status_label(row["status"]),
        "statusCode": row["status"],
        "approvedBy": decrypt_text(row["approved_by_enc"]) if row["approved_by_enc"] else "",
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def user_leave_requests(conn, user, year=None):
    year = int(year or date.today().year)
    ensure_leave_balance(conn, user, year)
    rows = conn.execute(
        """
        SELECT l.*, COALESCE(u.department, '') AS department
        FROM leave_requests l
        LEFT JOIN users_secure u ON u.id_lookup = l.user_id_lookup
        WHERE l.user_id_lookup = ? AND l.year = ?
        ORDER BY start_date DESC, id DESC
        """,
        (id_lookup(user.get("id", "")), year),
    ).fetchall()
    return [leave_request_payload(row) for row in rows]


def leave_approvals(conn, year=None):
    params = []
    where = ""
    if year:
        where = "WHERE l.year = ?"
        params.append(int(year))
    rows = conn.execute(
        f"""
        SELECT l.*, COALESCE(u.department, '') AS department
        FROM leave_requests l
        LEFT JOIN users_secure u ON u.id_lookup = l.user_id_lookup
        {where}
        ORDER BY
          CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
          start_date DESC,
          id DESC
        """,
        params,
    ).fetchall()
    return [leave_request_payload(row) for row in rows]


def target_leave_user(conn, user, payload):
    if is_admin(user):
        target_id = str(payload.get("userId") or payload.get("targetUserId") or "").strip()
        if target_id:
            row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(target_id),)).fetchone()
            if not row:
                raise ValueError("Leave target user not found.")
            return public_user(row)
    return user


def create_leave_request(conn, user, payload):
    target_user = target_leave_user(conn, user, payload)
    start_date = str(payload.get("startDate") or "").strip()
    end_date = str(payload.get("endDate") or start_date).strip()
    leave_type = str(payload.get("type") or "연차").strip()[:40]
    reason = str(payload.get("reason") or "").strip()[:120]
    try:
        days = float(payload.get("days") or 0)
    except (TypeError, ValueError):
        raise ValueError("Invalid leave days.")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", start_date) or not re.match(r"^\d{4}-\d{2}-\d{2}$", end_date):
        raise ValueError("Invalid leave date.")
    if days <= 0 or days > 30:
        raise ValueError("Invalid leave days.")
    year = leave_year(start_date)
    ensure_leave_balance(conn, target_user, year)
    conn.execute(
        """
        INSERT INTO leave_requests
          (user_id_lookup, user_id_enc, user_name_enc, year, start_date, end_date, days, leave_type, reason_enc, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (
            id_lookup(target_user.get("id", "")),
            encrypt_text(target_user.get("id", "")),
            encrypt_text(target_user.get("name", "")),
            year,
            start_date,
            end_date,
            days,
            leave_type,
            encrypt_text(reason),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )


def update_leave_status(conn, request_id, status, approver):
    status_code = leave_status_code(status)
    if status_code == "pending":
        raise ValueError("Invalid leave approval status.")
    row = conn.execute("SELECT * FROM leave_requests WHERE id = ?", (int(request_id),)).fetchone()
    if not row:
        raise ValueError("Leave request not found.")
    conn.execute(
        """
        UPDATE leave_requests
        SET status = ?,
            approved_by_enc = ?,
            approved_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            status_code,
            encrypt_text(approver.get("id", "")),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            int(request_id),
        ),
    )


def project_logs(conn, page=1, page_size=10):
    page = max(1, int(page or 1))
    page_size = max(1, min(100, int(page_size or 10)))
    offset = (page - 1) * page_size
    total = conn.execute("SELECT COUNT(*) AS count FROM project_logs").fetchone()["count"]
    rows = conn.execute(
        """
        SELECT id, user_id_enc, name_enc, role, action, category, project_no,
               project_name_enc, target, summary_enc, created_at
        FROM project_logs
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (page_size, offset),
    ).fetchall()
    logs = [
        {
            "id": row["id"],
            "userId": decrypt_text(row["user_id_enc"]) if row["user_id_enc"] else "",
            "name": decrypt_text(row["name_enc"]) if row["name_enc"] else "",
            "role": row["role"],
            "action": row["action"],
            "category": row["category"],
            "projectNo": row["project_no"],
            "projectName": decrypt_text(row["project_name_enc"]) if row["project_name_enc"] else "",
            "target": row["target"],
            "summary": decrypt_text(row["summary_enc"]) if row["summary_enc"] else "",
            "createdAt": row["created_at"],
        }
        for row in rows
    ]
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    return {
        "logs": logs,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": total_pages,
    }


def clear_project_logs(conn):
    conn.execute("DELETE FROM project_logs")
    conn.commit()


def log_project_actions(conn, user, entries):
    if not user or not entries:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_id = str(user.get("id") or "")
    name = str(user.get("name") or "")
    role = "admin" if user.get("role") == "admin" else "user"
    for entry in entries:
        action = str(entry.get("action") or "수정").strip() or "수정"
        category = str(entry.get("category") or "프로젝트").strip() or "프로젝트"
        project_no = str(entry.get("projectNo") or "").strip()
        project_name = str(entry.get("projectName") or "").strip()
        target = str(entry.get("target") or "").strip()
        summary = str(entry.get("summary") or "").strip()
        conn.execute(
            """
            INSERT INTO project_logs
              (user_id_enc, name_enc, role, action, category, project_no, project_name_enc, target, summary_enc, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                encrypt_text(user_id),
                encrypt_text(name),
                role,
                action,
                category,
                project_no,
                encrypt_text(project_name),
                target,
                encrypt_text(summary),
                now,
            ),
        )
    conn.commit()



def project_identity(project):
    return str(project.get("id") or project.get("projectNo") or project.get("no") or "").strip()


def project_log_entry(action, category, project, target="", summary=""):
    return {
        "action": action,
        "category": category,
        "projectNo": str(project.get("projectNo") or project.get("no") or "")[:80],
        "projectName": str(project.get("name") or "")[:200],
        "target": str(target or "")[:120],
        "summary": str(summary or "")[:500],
    }


def scalar_change_summary(field, before, after):
    before_text = str(before or "").strip()
    after_text = str(after or "").strip()
    if field == "depositDate":
        if before_text and not after_text:
            return "\uc644\ub8cc\uc77c\uc790 \uc0ad\uc81c"
        if not before_text and after_text:
            return "\uc644\ub8cc\uc77c\uc790 \ub4f1\ub85d"
        return "\uc644\ub8cc\uc77c\uc790 \uc218\uc815"
    if field in ("milestone", "adminMilestone"):
        return f"\ub9c8\uc77c\uc2a4\ud1a4 \ubcc0\uacbd: {before_text or '-'} -> {after_text or '-'}"
    if field in ("status", "progressStatus"):
        return f"\uc791\uc5c5\uc0c1\ud0dc \ubcc0\uacbd: {before_text or '-'} -> {after_text or '-'}"
    if field == "hasIssue":
        return "\uc774\uc288 \ub4f1\ub85d" if bool(after) else "\uc774\uc288 \ud574\uc81c"
    return f"{field} \ubcc0\uacbd"


def issue_signature(issue):
    return json.dumps({
        "memo": issue.get("memo") or issue.get("text") or "",
        "status": issue.get("status") or "",
        "type": issue.get("type") or "",
        "completed": bool(issue.get("completed")),
    }, ensure_ascii=False, sort_keys=True)


def schedule_signature(entry):
    return json.dumps({
        "date": entry.get("date") or "",
        "milestone": entry.get("milestone") or "",
        "detail": entry.get("detail") or "",
        "staffRole": entry.get("staffRole") or "",
        "staffName": entry.get("staffName") or "",
        "completed": bool(entry.get("completed")),
    }, ensure_ascii=False, sort_keys=True)


def schedule_target(entry):
    parts = [str(entry.get(key) or "") for key in ("date", "milestone", "detail") if entry.get(key)]
    return " \u00b7 ".join(parts) or "\uc77c\uc815"


def build_project_logs_from_diff(before_projects, after_projects):
    logs = []
    before_map = {project_identity(project): project for project in before_projects if isinstance(project, dict) and project_identity(project)}
    after_map = {project_identity(project): project for project in after_projects if isinstance(project, dict) and project_identity(project)}
    for key, project in before_map.items():
        if key not in after_map:
            logs.append(project_log_entry("\uc0ad\uc81c", "\ud504\ub85c\uc81d\ud2b8", project, summary="\ud504\ub85c\uc81d\ud2b8 \uc0ad\uc81c"))
    for key, project in after_map.items():
        previous = before_map.get(key)
        if not previous:
            logs.append(project_log_entry("\ub4f1\ub85d", "\ud504\ub85c\uc81d\ud2b8", project, summary="\ud504\ub85c\uc81d\ud2b8 \ub4f1\ub85d"))
            continue
        for field in ("depositDate", "milestone", "adminMilestone", "status", "progressStatus", "hasIssue"):
            if previous.get(field) != project.get(field):
                logs.append(project_log_entry("\uc218\uc815", "\ud504\ub85c\uc81d\ud2b8", project, target=field, summary=scalar_change_summary(field, previous.get(field), project.get(field))))
        before_issues = {str(issue.get("id") or index): issue for index, issue in enumerate(previous.get("issues") or []) if isinstance(issue, dict)}
        after_issues = {str(issue.get("id") or index): issue for index, issue in enumerate(project.get("issues") or []) if isinstance(issue, dict)}
        for issue_id, issue in before_issues.items():
            if issue_id not in after_issues:
                logs.append(project_log_entry("\uc0ad\uc81c", "\uc774\uc288", project, target="\uc774\uc288", summary="\uc774\uc288 \ub0b4\uc6a9 \uc0ad\uc81c"))
        for issue_id, issue in after_issues.items():
            old = before_issues.get(issue_id)
            if not old:
                logs.append(project_log_entry("\ub4f1\ub85d", "\uc774\uc288", project, target="\uc774\uc288", summary="\uc774\uc288 \ub0b4\uc6a9 \ub4f1\ub85d"))
            elif issue_signature(old) != issue_signature(issue):
                logs.append(project_log_entry("\uc218\uc815", "\uc774\uc288", project, target="\uc774\uc288", summary="\uc774\uc288 \ub0b4\uc6a9 \uc218\uc815"))
        before_schedules = {str(entry.get("id") or index): entry for index, entry in enumerate(previous.get("schedules") or []) if isinstance(entry, dict)}
        after_schedules = {str(entry.get("id") or index): entry for index, entry in enumerate(project.get("schedules") or []) if isinstance(entry, dict)}
        for entry_id, entry in before_schedules.items():
            if entry_id not in after_schedules:
                logs.append(project_log_entry("\uc0ad\uc81c", "\uc77c\uc815", project, target=schedule_target(entry), summary="\uc77c\uc815 \uc0ad\uc81c"))
        for entry_id, entry in after_schedules.items():
            old = before_schedules.get(entry_id)
            if not old:
                logs.append(project_log_entry("\ub4f1\ub85d", "\uc77c\uc815", project, target=schedule_target(entry), summary="\uc77c\uc815 \ub4f1\ub85d"))
            elif schedule_signature(old) != schedule_signature(entry):
                summary = "\uc77c\uc815 \uc644\ub8cc" if bool(entry.get("completed")) and not bool(old.get("completed")) else "\uc77c\uc815 \uc218\uc815"
                logs.append(project_log_entry("\uc218\uc815", "\uc77c\uc815", project, target=schedule_target(entry), summary=summary))
    return logs[:200]


def merge_projects_for_user(existing_projects, incoming_projects, user):
    if is_admin(user):
        return incoming_projects
    incoming_by_id = {project_identity(project): project for project in incoming_projects if isinstance(project, dict) and project_identity(project)}
    merged = []
    used = set()
    for project in existing_projects:
        key = project_identity(project)
        if key in incoming_by_id and user_can_access_project(user, project):
            candidate = incoming_by_id[key]
            merged.append(candidate if user_can_access_project(user, candidate) else project)
            used.add(key)
        else:
            merged.append(project)
    for key, project in incoming_by_id.items():
        if key not in used and user_can_access_project(user, project):
            merged.append(project)
    return merged


def cleanup_sessions():
    now = time.time()
    expired_tokens = [token for token, session in SESSIONS.items() if session.get("expires_at", 0) <= now]
    for token in expired_tokens:
        SESSIONS.pop(token, None)


def create_session(user):
    cleanup_sessions()
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    SESSIONS[token] = {
        "user": user,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return token


def session_from_token(token):
    cleanup_sessions()
    token = str(token or "")
    session = SESSIONS.get(token)
    if not session:
        return None
    if session.get("expires_at", 0) <= time.time():
        SESSIONS.pop(token, None)
        return None
    session["expires_at"] = time.time() + SESSION_TTL_SECONDS
    return session


def auth_token_from_handler(handler):
    auth = handler.headers.get("Authorization") or ""
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return handler.headers.get("X-Session-Token") or ""


def current_session(handler):
    return session_from_token(auth_token_from_handler(handler))


def current_user(handler):
    session = current_session(handler)
    if not session:
        return None
    return session.get("user")

def is_admin(user):
    return bool(user and user.get("role") == "admin")


def user_match_values(user):
    if not user:
        return set()
    return {str(user.get("id") or "").strip().lower(), str(user.get("name") or "").strip().lower()} - {""}


def user_can_access_project(user, project):
    if is_admin(user):
        return True
    values = user_match_values(user)
    if not values or not isinstance(project, dict):
        return False
    staff_fields = ("pm", "designer", "publisher", "programmer", "manager", "owner")
    return any(str(project.get(field) or "").strip().lower() in values for field in staff_fields)


def filter_projects_for_user(projects, user):
    if is_admin(user):
        return projects
    return [project for project in projects if user_can_access_project(user, project)]


def user_payload(user):
    if not user:
        return None
    return {
        "id": user.get("id", ""),
        "name": user.get("name", ""),
        "role": user.get("role", "user"),
        "approvalStatus": user.get("approvalStatus", ""),
        "department": user.get("department", ""),
    }

def is_active_account(row):
    if row["role"] == "admin":
        return True
    approval = str(row["approval_status"] or "")
    normalized = normalize_approval_status(approval, row["role"])
    return approval in ("활성화", "승인") or normalized in ("활성화", "승인")


def clear_session_token(token):
    if token:
        SESSIONS.pop(str(token), None)

def login_access_locked():
    return LOGIN_LOCKED or LOGIN_FAILURE_COUNT >= LOGIN_FAILURE_LIMIT


def record_login_failure():
    global LOGIN_FAILURE_COUNT, LOGIN_LOCKED
    LOGIN_FAILURE_COUNT += 1
    if LOGIN_FAILURE_COUNT >= LOGIN_FAILURE_LIMIT:
        LOGIN_LOCKED = True
        SESSIONS.clear()


def reset_login_failures():
    global LOGIN_FAILURE_COUNT, LOGIN_LOCKED
    LOGIN_FAILURE_COUNT = 0
    LOGIN_LOCKED = False


def records_as_json(conn, table, mode):
    if table == "project_records":
        rows = conn.execute("SELECT data_json FROM project_records WHERE mode = ? ORDER BY project_no, id", (mode,)).fetchall()
    elif table == "admin_project_records":
        rows = conn.execute("SELECT data_json FROM admin_project_records WHERE mode = ? ORDER BY project_no, id", (mode,)).fetchall()
    else:
        raise ValueError("Invalid table.")
    return sorted((json.loads(row["data_json"]) for row in rows), key=project_sort_key)


def dataset_snapshot(conn, mode, user=None):
    normalized_mode = normalize_mode(mode)
    if normalized_mode == "public" or not user:
        return {
            "mode": "public",
            "projects": public_sample_projects(),
            "adminProjects": [],
            "users": [],
            "loginUser": "",
            "currentUser": None,
        }
    projects = records_as_json(conn, "project_records", normalized_mode)
    return {
        "mode": normalized_mode,
        "projects": filter_projects_for_user(projects, user),
        "adminProjects": records_as_json(conn, "admin_project_records", normalized_mode) if is_admin(user) else [],
        "users": get_users(conn) if is_admin(user) else [],
        "loginUser": user.get("id", ""),
        "currentUser": user_payload(user),
    }


def public_sample_projects():
    projects = json.loads(json.dumps(SAMPLE_PROJECTS, ensure_ascii=False))
    today = date.today()
    if projects:
        projects[0]["depositDate"] = f"{today.year}-{today.month:02d}-05"
        projects[0]["status"] = "완료"
        projects[0]["progressStatus"] = "완료"
        projects[0]["clientContacts"] = [
            {
                "id": "sample-contact-search-001",
                "name": "샘플 담당자",
                "companyPhone": "02-1098-9001",
                "personalPhone": "010-1098-9001",
                "email": "sample@example.com",
            }
        ]
    return projects


def read_request_json(handler):
    length = int(handler.headers.get("Content-Length") or 0)
    if length > MAX_JSON_BODY_BYTES:
        raise ValueError("요청 데이터가 너무 큽니다.")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8")
    return json.loads(raw or "{}")


def decode_data_url(data_url):
    value = str(data_url or "")
    if not value:
        return b""
    match = re.match(r"^data:([^;,]+);base64,(.*)$", value, re.I | re.S)
    if not match:
        raise ValueError("첨부 파일 형식이 올바르지 않습니다.")
    mime_type = match.group(1).lower()
    if mime_type != "application/pdf":
        raise ValueError("PDF 파일만 업로드할 수 있습니다.")
    return base64.b64decode(match.group(2), validate=True)


def validate_pdf_payload(file_name, data_url):
    if not data_url:
        return
    if file_name and not str(file_name).lower().endswith(".pdf"):
        raise ValueError("PDF 확장자 파일만 업로드할 수 있습니다.")
    data = decode_data_url(data_url)
    if len(data) > MAX_PDF_BYTES:
        raise ValueError("PDF 파일은 10MB 이하만 업로드할 수 있습니다.")
    if not data.startswith(b"%PDF-"):
        raise ValueError("정상 PDF 파일이 아닙니다.")
    scan = data[: min(len(data), 2 * 1024 * 1024)]
    lowered = scan.lower()
    for marker in PDF_DANGEROUS_MARKERS:
        if marker.lower() in lowered:
            raise ValueError("보안상 위험한 PDF 기능이 포함되어 업로드할 수 없습니다.")


def validate_project_files(projects):
    for project in projects:
        validate_pdf_payload(project.get("quoteFileName"), project.get("quoteFileData"))

def read_text_asset(relative_path):
    path = BASE_DIR / relative_path
    return path.read_text(encoding="utf-8")


VIEW_PAGE_FILES = (
    "dashboard.html",
    "projects.html",
    "schedule.html",
    "vacation_schedule.html",
    "monthly.html",
    "issues.html",
    "departments.html",
    "members.html",
    "leave_management.html",
    "leave_approvals.html",
    "login_logs.html",
    "project_logs.html",
)


def render_project_page():
    template = read_text_asset("templates/base.html")
    pages_html = "".join(read_text_asset(f"pages/{filename}") for filename in VIEW_PAGE_FILES)
    replacements = {
        "{{HEADER}}": read_text_asset("templates/header.html"),
        "{{SIDEBAR}}": read_text_asset("templates/sidebar.html"),
        "{{PAGES}}": pages_html,
        "{{DETAIL}}": read_text_asset("pages/detail.html"),
        "{{DIALOGS}}": read_text_asset("pages/dialogs.html"),
        "{{FOOTER}}": read_text_asset("templates/footer.html"),
    }
    for token, value in replacements.items():
        template = template.replace(token, value)
    return template


class SQLiteDashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def write_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def write_error_json(self, message, status=HTTPStatus.BAD_REQUEST):
        self.write_json({"ok": False, "message": message}, status)

    def write_html(self, html, status=HTTPStatus.OK):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/agencyflow.html", "/project.html"):
            try:
                return self.write_html(render_project_page())
            except Exception:
                return self.write_error_json("Project page render failed.", HTTPStatus.INTERNAL_SERVER_ERROR)
        if not parsed.path.startswith("/api/"):
            return super().do_GET()
        try:
            with connect() as conn:
                if parsed.path == "/api/initialize":
                    user = current_user(self)
                    mode = "private" if user else "public"
                    return self.write_json(dataset_snapshot(conn, mode, user))
                if parsed.path == "/api/dataset":
                    mode = parse_qs(parsed.query).get("mode", ["public"])[0]
                    user = current_user(self)
                    if normalize_mode(mode) == "private" and not user:
                        return self.write_json(dataset_snapshot(conn, "public", None))
                    return self.write_json(dataset_snapshot(conn, mode, user))
                if parsed.path == "/api/login-user":
                    user = current_user(self)
                    return self.write_json({"loginUser": user.get("id", "") if user else "", "currentUser": user})
                if parsed.path == "/api/users":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"users": get_users(conn)})
                if parsed.path == "/api/departments":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"departments": get_departments(conn)})
                if parsed.path == "/api/company-holidays":
                    user = current_user(self)
                    if not user:
                        return self.write_json({"holidays": []})
                    query = parse_qs(parsed.query)
                    year = query.get("year", [""])[0] or None
                    return self.write_json({"holidays": company_holidays(conn, year)})
                if parsed.path == "/api/leaves":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    query = parse_qs(parsed.query)
                    year = int(query.get("year", [date.today().year])[0])
                    return self.write_json({"summary": leave_summary(conn, user, year), "requests": user_leave_requests(conn, user, year)})
                if parsed.path == "/api/leave-approvals":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    query = parse_qs(parsed.query)
                    year = query.get("year", [""])[0] or None
                    return self.write_json({"requests": leave_approvals(conn, year)})
                if parsed.path == "/api/leave-calendar":
                    user = current_user(self)
                    query = parse_qs(parsed.query)
                    year = query.get("year", [""])[0] or None
                    return self.write_json({"requests": leave_approvals(conn, year) if user else [], "holidays": company_holidays(conn, year) if user else []})
                if parsed.path == "/api/login-logs":
                    user = current_user(self)
                    if not user or user.get("role") != "admin":
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"logs": login_logs(conn)})
                if parsed.path == "/api/project-logs":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    query = parse_qs(parsed.query)
                    page = query.get("page", ["1"])[0]
                    page_size = query.get("pageSize", ["10"])[0]
                    return self.write_json(project_logs(conn, page, page_size))
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        try:
            payload = read_request_json(self)
            with connect() as conn:
                if parsed.path == "/api/projects":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True})
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    incoming_projects = payload.get("projects") or []
                    if not isinstance(incoming_projects, list):
                        return self.write_error_json("Invalid project payload.", HTTPStatus.BAD_REQUEST)
                    validate_project_files(incoming_projects)
                    before_projects = records_as_json(conn, "project_records", mode)
                    projects = merge_projects_for_user(before_projects, incoming_projects, user)
                    conn.execute("DELETE FROM project_records WHERE mode = ?", (mode,))
                    insert_projects(conn, mode, projects)
                    logs = build_project_logs_from_diff(before_projects, projects)
                    if logs:
                        log_project_actions(conn, user, logs)
                    conn.commit()
                    return self.write_json({"ok": True, "logged": len(logs)})
                if parsed.path == "/api/admin-projects":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True})
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    admin_projects = payload.get("adminProjects") or []
                    if not isinstance(admin_projects, list):
                        return self.write_error_json("Invalid admin project payload.", HTTPStatus.BAD_REQUEST)
                    conn.execute("DELETE FROM admin_project_records WHERE mode = ?", (mode,))
                    insert_admin_projects(conn, mode, admin_projects)
                    conn.commit()
                    return self.write_json({"ok": True})
                if parsed.path == "/api/login-user":
                    return self.write_json({"ok": True})
                if parsed.path.startswith("/api/leaves/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    suffix = parsed.path.split("/api/leaves/", 1)[1]
                    parts = suffix.split("/")
                    if len(parts) == 2 and parts[1] == "approval":
                        update_leave_status(conn, parts[0], payload.get("status") or "approved", user)
                        conn.commit()
                        return self.write_json({"ok": True, "requests": leave_approvals(conn)})
                if parsed.path.startswith("/api/users/"):
                    user = current_user(self)
                    if not user or user.get("role") != "admin":
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    user_id = unquote(parsed.path.split("/api/users/", 1)[1])
                    return self.update_user(conn, user_id, payload)
                if parsed.path.startswith("/api/departments/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    department_id = unquote(parsed.path.split("/api/departments/", 1)[1])
                    update_department(conn, department_id, payload.get("name"))
                    conn.commit()
                    return self.write_json({"ok": True, "departments": get_departments(conn), "users": get_users(conn)})
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            payload = read_request_json(self)
            with connect() as conn:
                if parsed.path == "/api/authenticate":
                    return self.authenticate(conn, payload)
                if parsed.path == "/api/users":
                    user = current_user(self)
                    if not user or user.get("role") != "admin":
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.create_user(conn, payload)
                if parsed.path == "/api/departments":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    create_department(conn, payload.get("name"))
                    conn.commit()
                    return self.write_json({"ok": True, "departments": get_departments(conn)})
                if parsed.path == "/api/company-holidays":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    create_company_holiday(conn, payload, user)
                    conn.commit()
                    return self.write_json({"ok": True, "holidays": company_holidays(conn)})
                if parsed.path == "/api/leaves":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    target_user = target_leave_user(conn, user, payload)
                    create_leave_request(conn, user, payload)
                    conn.commit()
                    year = leave_year(payload.get("startDate"))
                    return self.write_json({"ok": True, "summary": leave_summary(conn, target_user, year), "requests": user_leave_requests(conn, target_user, year)})
                if parsed.path == "/api/project-logs":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_error_json("Project logs are recorded by the server.", HTTPStatus.METHOD_NOT_ALLOWED)
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        try:
            with connect() as conn:
                if parsed.path == "/api/project-logs":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    clear_project_logs(conn)
                    return self.write_json({"ok": True})
                if parsed.path == "/api/login-user":
                    clear_session_token(auth_token_from_handler(self))
                    return self.write_json({"ok": True})
                if parsed.path.startswith("/api/departments/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    department_id = unquote(parsed.path.split("/api/departments/", 1)[1])
                    delete_department(conn, department_id)
                    conn.commit()
                    return self.write_json({"ok": True, "departments": get_departments(conn)})
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def authenticate(self, conn, payload):
        user_id = str(payload.get("id") or "").strip()
        password = str(payload.get("password") or "").strip()
        ip = self.client_address[0] if self.client_address else ""
        if login_access_locked():
            log_login_attempt(conn, user_id, "", "user", "failure", "로그인 실패 한도 초과", ip)
            return self.write_json({"ok": False, "message": "로그인 시도가 5회 이상 실패하여 잠시 동안 잠겼습니다. 서버를 다시 시작해야 잠금이 해제됩니다."}, HTTPStatus.TOO_MANY_REQUESTS)
        row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone()
        if not row:
            log_login_attempt(conn, user_id, "", "user", "failure", "아이디 또는 비밀번호 불일치", ip)
            record_login_failure()
            return self.write_json({"ok": False, "message": "아이디 또는 비밀번호가 올바르지 않습니다."})
        user = public_user(row)
        if not verify_password(password, row["password"]):
            log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "아이디 또는 비밀번호 불일치", ip)
            record_login_failure()
            return self.write_json({"ok": False, "message": "아이디 또는 비밀번호가 올바르지 않습니다."})
        approval = normalize_approval_status(row["approval_status"], row["role"])
        if not is_active_account(row):
            log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "비활성화 계정", ip)
            record_login_failure()
            return self.write_json({"ok": False, "message": "계정이 비활성화되었습니다. 관리자에게 문의하세요."})
        reset_login_failures()
        if password_needs_rehash(row["password"]):
            upsert_secure_user(conn, user["id"], hash_password(password), user.get("name", ""), user.get("role", "user"), approval, user.get("department", ""))
        log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "success", "", ip)
        token = create_session(user)
        return self.write_json({"ok": True, "user": user_payload(user), "token": token, "expiresIn": SESSION_TTL_SECONDS, "users": get_users(conn) if is_admin(user) else []})

    def create_user(self, conn, payload):
        user_id = str(payload.get("id") or "").strip()
        password = str(payload.get("password") or "").strip()
        name = str(payload.get("name") or "").strip()
        role = "admin" if payload.get("role") == "admin" else "user"
        approval = normalize_approval_status(payload.get("approvalStatus"), role)
        department = normalize_department(payload.get("department"))
        if not re.match(r"^[A-Za-z0-9_.@-]{1,80}$", user_id):
            return self.write_json({"ok": False, "message": "아이디 형식이 올바르지 않습니다.", "users": get_users(conn)})
        if not password or not name:
            return self.write_json({"ok": False, "message": "아이디, 비밀번호, 이름을 모두 입력하세요.", "users": get_users(conn)})
        if conn.execute("SELECT 1 FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone():
            return self.write_json({"ok": False, "message": "이미 사용 중인 아이디입니다.", "users": get_users(conn)})
        upsert_secure_user(conn, user_id, hash_password(password), name[:80], role, approval, department)
        conn.commit()
        row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone()
        return self.write_json({"ok": True, "user": public_user(row), "users": get_users(conn), "message": "회원이 등록되었습니다."})

    def update_user(self, conn, user_id, payload):
        row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone()
        if not row:
            return self.write_json({"ok": False, "message": "회원을 찾을 수 없습니다.", "users": get_users(conn)})
        current = public_user(row)
        name = str(payload.get("name") if payload.get("name") is not None else current["name"]).strip()[:80]
        role = "admin" if payload.get("role") == "admin" else "user"
        approval = normalize_approval_status(payload.get("approvalStatus"), role)
        department = normalize_department(payload.get("department") if payload.get("department") is not None else current.get("department", ""))
        password = row["password"]
        if current["id"].lower() == DEFAULT_ADMIN_ID:
            role = "admin"
            approval = "활성화"
        if str(payload.get("password") or "").strip():
            password = hash_password(str(payload.get("password")).strip())
        upsert_secure_user(conn, current["id"], password, name, role, approval, department)
        conn.commit()
        next_row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(current["id"]),)).fetchone()
        return self.write_json({"ok": True, "user": public_user(next_row), "users": get_users(conn)})


def run(port=8766):
    ensure_db()
    server = ThreadingHTTPServer(("127.0.0.1", port), SQLiteDashboardHandler)
    print(f"SQLite dashboard server: http://127.0.0.1:{port}/agencyflow.html")
    print(f"SQLite database: {DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    run(int(os.environ.get("PORT", "8766")))
