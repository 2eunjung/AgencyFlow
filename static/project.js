const APP_CRYPTO_SECRET = "pm-dashboard-portfolio-crypto-v1";
const APP_CRYPTO_SALT = "pm-dashboard-salt-v1";
const PASSWORD_HASH_PREFIX = "pbkdf2:100000:";
const SESSION_TOKEN_KEY = "project_session_token";
const LEGACY_AUTH_STORAGE_KEYS = ["login_user", "current_user", "session", "session_token", "project_session_token"];

class SecureDataStore {
  constructor() {
    this.keyPromise = null;
  }

  ready() {
    if (!this.keyPromise) {
      this.keyPromise = this.deriveKey();
    }
    return this.keyPromise;
  }

  async deriveKey() {
    if (!globalThis.crypto?.subtle) {
      throw new Error("Web Crypto API를 사용할 수 없습니다. http://localhost 또는 https로 접속해 주세요.");
    }
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey("raw", enc.encode(APP_CRYPTO_SECRET), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(APP_CRYPTO_SALT),
        iterations: 120000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  bytesToBase64(bytes) {
    let binary = "";
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    view.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async encryptJson(value) {
    const key = await this.ready();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(value));
    const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
    const cipherBytes = new Uint8Array(cipherBuffer);
    const combined = new Uint8Array(iv.length + cipherBytes.length);
    combined.set(iv, 0);
    combined.set(cipherBytes, iv.length);
    return `enc:v1:${this.bytesToBase64(combined)}`;
  }

  async decryptJson(raw) {
    if (raw == null || raw === "") return null;
    const text = String(raw);

    if (!text.startsWith("enc:v1:")) {
      try {
        return JSON.parse(text);
      } catch (error) {
        return null;
      }
    }

    try {
      const key = await this.ready();
      const combined = this.base64ToBytes(text.slice("enc:v1:".length));
      if (combined.length <= 12) return null;
      const iv = combined.slice(0, 12);
      const cipherBytes = combined.slice(12);
      const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBytes);
      return JSON.parse(new TextDecoder().decode(plainBuffer));
    } catch (error) {
      console.warn("Encrypted storage could not be decrypted.", error);
      return null;
    }
  }

  async derivePasswordBits(password, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      256
    );
    return this.bytesToBase64(new Uint8Array(bits));
  }

  async hashPassword(password, saltBytes) {
    const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
    const hashPart = await this.derivePasswordBits(password, salt);
    return `${PASSWORD_HASH_PREFIX}${this.bytesToBase64(salt)}:${hashPart}`;
  }

  async verifyPassword(password, stored) {
    const value = String(stored || "");
    try {
      if (value.startsWith(PASSWORD_HASH_PREFIX)) {
        const body = value.slice(PASSWORD_HASH_PREFIX.length);
        const separator = body.lastIndexOf(":");
        if (separator <= 0) return false;
        const saltPart = body.slice(0, separator);
        const hashPart = body.slice(separator + 1);
        if (!saltPart || !hashPart) return false;
        const computed = await this.derivePasswordBits(password, this.base64ToBytes(saltPart));
        return computed === hashPart;
      }

      // 이전 해시 포맷 호환: pbkdf2$100000$salt$hash
      if (value.startsWith("pbkdf2$100000$")) {
        const body = value.slice("pbkdf2$100000$".length);
        const separator = body.lastIndexOf("$");
        if (separator <= 0) return false;
        const saltPart = body.slice(0, separator);
        const hashPart = body.slice(separator + 1);
        if (!saltPart || !hashPart) return false;
        const computed = await this.derivePasswordBits(password, this.base64ToBytes(saltPart));
        return computed === hashPart;
      }

      return value === String(password || "");
    } catch (error) {
      console.warn("Password verification failed.", error);
      return false;
    }
  }
}


class SQLiteProjectRepository {
  constructor({ apiBase = "./api" } = {}) {
    this.apiBase = apiBase;
    this.mode = "public";
    this.projects = [];
    this.assignmentProjects = [];
    this.adminProjects = [];
    this.usersCache = [];
    this.loginLogsCache = [];
    this.projectLogsCache = [];
    this.projectLogsMeta = { total: 0, page: 1, pageSize: 10, totalPages: 1 };
    this.leaveSummaryCache = { totalDays: 0, usedDays: 0, remainingDays: 0 };
    this.leaveRequestsCache = [];
    this.leaveApprovalsCache = [];
    this.vacationScheduleCache = [];
    this.departmentsCache = [];
    this.companyHolidaysCache = [];
    this.loginUser = "";
    this.currentUser = null;
    this.sessionToken = this.readSessionToken();
    this.clearLegacyAuthStorage();
  }

  readSessionToken() {
    try {
      return sessionStorage.getItem(SESSION_TOKEN_KEY) || "";
    } catch (error) {
      return "";
    }
  }

  writeSessionToken(token) {
    this.sessionToken = String(token || "");
    try {
      if (this.sessionToken) {
        sessionStorage.setItem(SESSION_TOKEN_KEY, this.sessionToken);
      } else {
        sessionStorage.removeItem(SESSION_TOKEN_KEY);
      }
    } catch (error) {
      this.sessionToken = "";
    }
  }

  clearLegacyAuthStorage() {
    try {
      LEGACY_AUTH_STORAGE_KEYS.forEach((key) => localStorage.removeItem(key));
      Object.keys(localStorage)
        .filter((key) => /login_user|current_user|session/i.test(key))
        .forEach((key) => localStorage.removeItem(key));
    } catch (error) {}
    try {
      ["login_user", "current_user", "session"].forEach((key) => sessionStorage.removeItem(key));
    } catch (error) {}
  }

  async api(path, options = {}) {
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    };
    if (this.sessionToken) {
      headers.Authorization = `Bearer ${this.sessionToken}`;
    }
    const response = await fetch(`${this.apiBase}${path}`, {
      cache: "no-store",
      headers,
      ...options,
    });
    const text = await response.text();
    const payload = text ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error(payload?.message || `SQLite API request failed: ${response.status}`);
    }
    return payload;
  }

  async initialize() {
    const snapshot = await this.api("/initialize");
    this.applySnapshot(snapshot);
    return this.getSnapshot();
  }

  async loadDataset(mode = "public") {
    const snapshot = await this.api(`/dataset?mode=${encodeURIComponent(mode)}`);
    this.applySnapshot(snapshot);
    return this.getSnapshot();
  }

  applySnapshot(snapshot = {}) {
    this.mode = snapshot.mode === "private" ? "private" : "public";
    this.projects = this.clone(snapshot.projects || []);
    this.scheduleProjects = this.clone(snapshot.scheduleProjects || snapshot.projects || []);
    this.assignmentProjects = this.clone(snapshot.assignmentProjects || snapshot.projects || []);
    this.adminProjects = this.clone(snapshot.adminProjects || []);
    this.usersCache = this.clone(snapshot.users || []);
    this.loginUser = typeof snapshot.loginUser === "string" ? snapshot.loginUser : "";
    this.currentUser = snapshot.currentUser || null;
    if (!this.loginUser) {
      this.currentUser = null;
      this.writeSessionToken("");
    }
  }

  async getSnapshot() {
    return {
      projects: this.clone(this.projects),
      scheduleProjects: this.clone(this.scheduleProjects || this.projects),
      assignmentProjects: this.clone(this.assignmentProjects || this.projects),
      adminProjects: this.clone(this.adminProjects),
      loginUser: this.loginUser,
      currentUser: this.currentUser,
    };
  }

  async saveProjects(projects) {
    this.projects = this.clone(projects);
    const result = await this.api("/projects", {
      method: "PUT",
      body: JSON.stringify({ mode: this.mode, projects: this.projects }),
    });
    if (result.projects) this.applySnapshot({ ...result, mode: this.mode });
    return this.getSnapshot();
  }

  async saveProjectAssignments(assignments) {
    const result = await this.api("/project-assignments", {
      method: "PUT",
      body: JSON.stringify({ mode: this.mode, projects: this.clone(assignments) }),
    });
    if (result.projects) this.projects = this.clone(result.projects);
    if (result.assignmentProjects) this.assignmentProjects = this.clone(result.assignmentProjects);
    if (result.scheduleProjects) this.scheduleProjects = this.clone(result.scheduleProjects);
    return result;
  }

  async advanceProjectCompletion(projectId, action = "approve", reason = "", completionType = "", memo = "") {
    const result = await this.api("/project-completion", {
      method: "POST",
      body: JSON.stringify({ mode: this.mode, projectId, action, reason, completionType, memo }),
    });
    this.applySnapshot(result);
    return this.getSnapshot();
  }

  saveAdminProjects(adminProjects) {
    this.adminProjects = this.clone(adminProjects);
    void this.api("/admin-projects", {
      method: "PUT",
      body: JSON.stringify({ mode: this.mode, adminProjects: this.adminProjects }),
    });
  }

  async getLoginUser() {
    const result = await this.api("/login-user");
    this.loginUser = typeof result.loginUser === "string" ? result.loginUser : "";
    this.currentUser = result.currentUser || null;
    if (!this.loginUser) this.writeSessionToken("");
    return this.loginUser;
  }

  setSession(result = {}) {
    this.writeSessionToken(result.token || "");
    this.currentUser = result.user || null;
    this.loginUser = this.currentUser?.id || "";
  }

  async setLoginUser(loginUser) {
    this.loginUser = String(loginUser || "");
  }

  clearLoginUser() {
    this.loginUser = "";
    this.currentUser = null;
    this.writeSessionToken("");
    void this.api("/login-user", { method: "DELETE" });
  }

  normalizeApprovalStatus(status, role = "user") {
    if (status === "활성화" || status === "승인") return "활성화";
    if (status === "비활성화" || status === "대기" || status === "거부") return "비활성화";
    return role === "admin" ? "활성화" : "비활성화";
  }

  normalizeUser(user) {
    const role = ["admin", "team_lead", "user"].includes(user?.role) ? user.role : "user";
    return {
      id: String(user?.id || "").trim(),
      password: String(user?.password || ""),
      name: String(user?.name || "").trim(),
      role,
      approvalStatus: this.normalizeApprovalStatus(user?.approvalStatus, role),
      department: String(user?.department || "").trim(),
      position: String(user?.position || "").trim(),
      hireDate: String(user?.hireDate || "").trim(),
      resignDate: String(user?.resignDate || "").trim(),
    };
  }

  getUsers() {
    return this.clone(this.usersCache || []);
  }

  async refreshUsers() {
    const result = await this.api("/users");
    this.usersCache = this.clone(result.users || []);
    return this.getUsers();
  }

  getDepartments() {
    return this.clone(this.departmentsCache || []);
  }

  async refreshDepartments() {
    const result = await this.api("/departments");
    this.departmentsCache = this.clone(result.departments || []);
    return this.getDepartments();
  }

  async createDepartment(name, color = "#d9eadf") {
    const result = await this.api("/departments", {
      method: "POST",
      body: JSON.stringify({ name, color }),
    });
    this.departmentsCache = this.clone(result.departments || []);
    return result;
  }

  async updateDepartment(id, name, color = "#d9eadf") {
    const result = await this.api(`/departments/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify({ name, color }),
    });
    this.departmentsCache = this.clone(result.departments || []);
    if (result.users) this.usersCache = this.clone(result.users);
    return result;
  }

  async deleteDepartment(id) {
    const result = await this.api(`/departments/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    this.departmentsCache = this.clone(result.departments || []);
    return result;
  }

  getLoginLogs() {
    return this.clone(this.loginLogsCache || []);
  }

  async refreshLoginLogs() {
    const result = await this.api("/login-logs");
    this.loginLogsCache = this.clone(result.logs || []);
    return this.getLoginLogs();
  }

  getProjectLogs() {
    return this.clone(this.projectLogsCache || []);
  }

  getProjectLogsMeta() {
    return { ...(this.projectLogsMeta || { total: 0, page: 1, pageSize: 10, totalPages: 1 }) };
  }

  getLeaveSummary() {
    return { ...(this.leaveSummaryCache || { totalDays: 0, usedDays: 0, remainingDays: 0 }) };
  }

  getLeaveRequests() {
    return this.clone(this.leaveRequestsCache || []);
  }

  getLeaveApprovals() {
    return this.clone(this.leaveApprovalsCache || []);
  }

  getVacationSchedule() {
    return this.clone(this.vacationScheduleCache || []);
  }

  getCompanyHolidays() {
    return this.clone(this.companyHolidaysCache || []);
  }

  async refreshLeaves() {
    const result = await this.api("/leaves");
    this.leaveSummaryCache = this.clone(result.summary || {});
    this.leaveRequestsCache = this.clone(result.requests || []);
    return { summary: this.getLeaveSummary(), requests: this.getLeaveRequests() };
  }

  async createLeaveRequest(payload) {
    const result = await this.api("/leaves", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    this.leaveSummaryCache = this.clone(result.summary || this.leaveSummaryCache);
    this.leaveRequestsCache = this.clone(result.requests || this.leaveRequestsCache);
    return result;
  }

  async refreshLeaveApprovals() {
    const result = await this.api("/leave-approvals");
    this.leaveApprovalsCache = this.clone(result.requests || []);
    return this.getLeaveApprovals();
  }

  async refreshVacationSchedule() {
    const result = await this.api("/leave-calendar");
    this.vacationScheduleCache = this.clone(result.requests || []);
    this.companyHolidaysCache = this.clone(result.holidays || []);
    if (result.departments) this.departmentsCache = this.clone(result.departments || []);
    return this.getVacationSchedule();
  }

  async createCompanyHoliday(payload) {
    const result = await this.api("/company-holidays", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    this.companyHolidaysCache = this.clone(result.holidays || []);
    return result;
  }

  async updateCompanyHoliday(id, payload) {
    const result = await this.api(`/company-holidays/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    this.companyHolidaysCache = this.clone(result.holidays || []);
    return result;
  }

  async deleteCompanyHoliday(id) {
    const result = await this.api(`/company-holidays/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    this.companyHolidaysCache = this.clone(result.holidays || []);
    return result;
  }

  async approveLeaveRequest(id, status = "approved") {
    const result = await this.api(`/leaves/${encodeURIComponent(id)}/approval`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
    this.leaveApprovalsCache = this.clone(result.requests || this.leaveApprovalsCache);
    return result;
  }

  async refreshProjectLogs(page = 1, pageSize = 10) {
    const result = await this.api(`/project-logs?page=${encodeURIComponent(page)}&pageSize=${encodeURIComponent(pageSize)}`);
    this.projectLogsCache = this.clone(result.logs || []);
    this.projectLogsMeta = {
      total: Number(result.total) || 0,
      page: Number(result.page) || page,
      pageSize: Number(result.pageSize) || pageSize,
      totalPages: Number(result.totalPages) || 1,
    };
    return { logs: this.getProjectLogs(), meta: this.getProjectLogsMeta() };
  }

  async appendProjectLogs(logs = []) {
    if (!Array.isArray(logs) || !logs.length) return { ok: true, count: 0 };
    const result = await this.api("/project-logs", {
      method: "POST",
      body: JSON.stringify({ logs }),
    });
    return result;
  }

  resetProjectLogsCache() {
    this.projectLogsCache = [];
    this.projectLogsMeta = { total: 0, page: 1, pageSize: 10, totalPages: 1 };
  }

  async clearAllProjectLogs() {
    await this.api("/project-logs", { method: "DELETE" });
    this.resetProjectLogsCache();
    return { ok: true };
  }

  async createUser({ id, password, name, role = "user", approvalStatus = "비활성화", department = "", position = "", hireDate = "", resignDate = "" }) {
    const result = await this.api("/users", {
      method: "POST",
      body: JSON.stringify({ id, password, name, role, approvalStatus, department, position, hireDate, resignDate }),
    });
    this.usersCache = this.clone(result.users || this.usersCache);
    return result;
  }

  async updateUser(id, patch = {}) {
    const result = await this.api(`/users/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(patch),
    });
    this.usersCache = this.clone(result.users || this.usersCache);
    return result;
  }

  async authenticateUser(id, password) {
    const result = await this.api("/authenticate", {
      method: "POST",
      body: JSON.stringify({ id, password }),
    });
    if (result.users) this.usersCache = this.clone(result.users);
    if (result.ok) this.setSession(result);
    return result;
  }

  findUser(id) {
    const normalizedId = String(id || "").trim();
    const user = this.getUsers().find((item) => item.id.toLowerCase() === normalizedId.toLowerCase());
    return user ? this.toPublicUser(user) : null;
  }

  toPublicUser(user) {
    const normalized = this.normalizeUser(user);
    return {
      id: normalized.id,
      name: normalized.name,
      role: normalized.role,
      approvalStatus: normalized.approvalStatus,
      department: normalized.department,
      position: normalized.position,
      hireDate: normalized.hireDate,
      resignDate: normalized.resignDate,
    };
  }

  clone(value) {
    return JSON.parse(JSON.stringify(value));
  }
}

window.projectRepository = new SQLiteProjectRepository();

const projectRepository = window.projectRepository;

let projects = [];
let scheduleProjects = [];
let assignmentProjects = [];
let adminProjects = [];
let currentView = "dashboard";
let projectLogPage = 1;
const PROJECT_LOG_PAGE_SIZE = 10;
const UI_SESSION_STATE_KEY = "agencyflow.ui.state";
let selectedId = null;
let loginUser = "";
let currentUser = null;
let vacationCursor = currentKstYearMonth();
let vacationWeekAnchor = todayDate();
let editingCompanyHolidayId = "";
let selectedLeaveUserId = "";
let selectedVacationLeaveUserId = "";
const KOREA_PUBLIC_HOLIDAYS = [
  { date: "2026-01-01", title: "신정" },
  { date: "2026-02-16", title: "설날 연휴" },
  { date: "2026-02-17", title: "설날" },
  { date: "2026-02-18", title: "설날 연휴" },
  { date: "2026-03-01", title: "삼일절" },
  { date: "2026-05-05", title: "어린이날" },
  { date: "2026-05-24", title: "부처님오신날" },
  { date: "2026-06-06", title: "현충일" },
  { date: "2026-08-15", title: "광복절" },
  { date: "2026-09-24", title: "추석 연휴" },
  { date: "2026-09-25", title: "추석" },
  { date: "2026-09-26", title: "추석 연휴" },
  { date: "2026-09-27", title: "추석 연휴" },
  { date: "2026-10-03", title: "개천절" },
  { date: "2026-10-09", title: "한글날" },
  { date: "2026-12-25", title: "성탄절" },
];
let progressStatusFilter = "";
let milestoneFilter = "";
let selectedMilestoneFilters = [];
let selectedStatusFilters = [];
let selectedProjectOptionFilters = ["excludeClosed"];
let editingStatusProjectId = "";
let isCreatingProject = false;
let draftProject = null;
let editingIssueId = "";
let editingContactId = "";
let editingCommunicationId = "";
let editingProjectWorkStackId = "";
let scheduleCursor = currentKstYearMonth();
let scheduleWeekAnchor = todayDate();
let scheduleDialogEditId = "";
let scheduleUiReady = false;
const listSortState = { projects: { key: "", direction: "" }, monthly: { key: "", direction: "" }, issues: { key: "", direction: "" } };
let projectsPersistSnapshot = [];
const CLOSED_WORK_STATUSES = ["작업중단", "계약해지", "종결"];
const CLOSED_MILESTONES = ["종결", "프로젝트종료", "작업중단-고객요청", "내용증명", "법정다툼"];
const INACTIVE_PROGRESS_MILESTONES = [
  "연락두절",
  "작업중단",
  "작업중단-고객요청",
  "내용증명",
  "법정다툼",
  "프로젝트종료",
];

const $ = (id) => document.getElementById(id);
const valueOf = (id, fallback = "") => $(id)?.value ?? fallback;
const checkedOf = (id, fallback = false) => $(id)?.checked ?? fallback;
const setValue = (id, value) => {
  const element = $(id);
  if (element) element.value = value;
};
const setChecked = (id, value) => {
  const element = $(id);
  if (element) element.checked = Boolean(value);
};
const setText = (id, value) => {
  const element = $(id);
  if (element) element.textContent = value;
};
const on = (id, eventName, handler) => {
  const element = $(id);
  if (element) element.addEventListener(eventName, handler);
};
const editableFields = [
  "name",
  "projectNo",
  "status",
  "milestone",
  "contractDate",
  "dueDate",
  "depositDate",
  "openDate",
  "contractAmount",
  "balance",
  "industry",
  "pm",
  "designer",
  "publisher",
  "programmer",
  "shortcutUrl",
  "intranetUrl",
  "designUrl",
];
const projectStaffFields = ["pm", "designer", "publisher", "programmer"];
let quoteUploadProjectId = "";
let editingShortcutProjectId = "";
let editingShortcutField = "shortcutUrl";

function hasProjectNo(project) {
  return String(project.projectNo ?? "").trim() !== "";
}

function nextProjectNo(projectList = projects) {
  const used = new Set(
    (projectList || [])
      .map((project) => String(project?.projectNo || "").trim())
      .filter(Boolean)
  );
  let number = 0;
  while (used.has(String(number).padStart(5, "0"))) number += 1;
  return String(number).padStart(5, "0");
}

function normalizeProject(project) {
  const clientContacts = project.clientContacts?.length
    ? project.clientContacts
    : project.clientName || project.clientPhone || project.clientEmail
      ? [
          {
            id: crypto.randomUUID(),
            name: project.clientName || "",
            companyPhone: project.clientPhone || "",
            personalPhone: "",
            email: project.clientEmail || "",
          },
        ]
      : [];
  const communications = project.communications?.length
    ? project.communications
    : project.communicationLog
      ? [
          {
            id: crypto.randomUUID(),
            date: todayDate(),
            memo: project.communicationLog,
          },
        ]
      : [];
  return {
    ...project,
    id: String(project.id || crypto.randomUUID()),
    name: String(project.name || "").replace(/^\d{5}_/, ""),
    issues: (project.issues || []).map(normalizeIssue),
    clientContacts,
    communications,
    schedules: (project.schedules || []).map((entry) => normalizeScheduleEntry(project, entry)),
    completionFlow: normalizeProjectCompletionFlow(project.completionFlow),
    pmId: project.pmId || "",
    pmAssignedAt: project.pmAssignedAt || "",
    designerId: project.designerId || "",
    designerAssignedAt: project.designerAssignedAt || "",
    publisherId: project.publisherId || "",
    publisherAssignedAt: project.publisherAssignedAt || "",
    programmerId: project.programmerId || "",
    programmerAssignedAt: project.programmerAssignedAt || "",
    monthlyCollection: Boolean(project.monthlyCollection),
    hasLanding: Boolean(project.hasLanding),
    hasIssue: Boolean(project.hasIssue),
    hostingType: project.hostingType || "일반 웹호스팅",
    shortcutUrl: project.shortcutUrl || "",
    intranetUrl: project.intranetUrl || "",
    designUrl: project.designUrl || "",
  };
}

function normalizeScheduleEntry(project, entry) {
  const fallbackStaff = scheduleStaffForMilestone(project, entry?.milestone || projectMilestone(project));
  const legacyStaffName = String(entry?.staff || "").trim();
  return {
    ...entry,
    staffRole: entry?.staffRole || fallbackStaff.staffRole,
    staffName: entry?.staffName || legacyStaffName || fallbackStaff.staffName,
    createdById: entry?.createdById || "",
    createdByName: entry?.createdByName || "",
    createdAt: entry?.createdAt || "",
    completed: Boolean(entry?.completed),
  };
}

function kstDateParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  })
    .formatToParts(date)
    .reduce((acc, part) => {
      acc[part.type] = part.value;
      return acc;
    }, {});
  return { year: Number(parts.year), month: Number(parts.month), day: Number(parts.day) };
}

function todayDate() {
  const parts = kstDateParts();
  return `${parts.year}-${String(parts.month).padStart(2, "0")}-${String(parts.day).padStart(2, "0")}`;
}

function currentKstYearMonth() {
  const parts = kstDateParts();
  return { year: parts.year, month: parts.month };
}

function issueStatusOptions() {
  return ["확인 필요", "고객 확인중", "내부 검토중", "장기지연", "프로젝트 참고"];
}

function issueTypeOptions() {
  return ["일정지연", "디자인 컴플레인", "기능 오류", "연락두절", "자료미제공", "피드백 지연"];
}

function normalizeIssueStatus(value, fallback = "확인 필요") {
  const options = issueStatusOptions();
  const raw = String(value || "").trim();
  if (options.includes(raw)) return raw;
  const aliases = {
    접수: "확인 필요",
    진행중: "확인 필요",
    고객확인: "고객 확인중",
    보류: "내부 검토중",
    해결완료: "프로젝트 참고",
  };
  return aliases[raw] || fallback;
}

function normalizeIssueType(value, fallback = "") {
  const options = issueTypeOptions();
  const raw = String(value || "").trim();
  if (options.includes(raw)) return raw;
  const aliases = {
    일정: "일정지연",
    품질: "디자인 컴플레인",
    커뮤니케이션: "연락두절",
    범위변경: "기능 오류",
    "결제/수금": "자료미제공",
    기술: "기능 오류",
    기타: "일정지연",
  };
  return aliases[raw] || fallback;
}

function normalizeIssue(issue) {
  const memo = String(issue?.memo || issue?.title || "").trim();
  const createdAt = issue?.createdAt || new Date().toISOString();
  const rawStatus = String(issue?.status || "").trim();
  const status = normalizeIssueStatus(issue?.status, memo ? "확인 필요" : "");
  const type = normalizeIssueType(issue?.type, "");
  const resolved = Boolean(issue?.resolved) || rawStatus === "해결완료";
  return {
    id: String(issue?.id || crypto.randomUUID()),
    status: resolved ? "프로젝트 참고" : status,
    type,
    memo,
    date: issue?.date || createdAt.slice(0, 10) || todayDate(),
    createdAt,
    createdById: issue?.createdById || "",
    createdByName: issue?.createdByName || "",
    resolved,
  };
}

function entryAuthorName(entry) {
  return String(entry?.createdByName || entry?.authorName || entry?.writer || "").trim() || "-";
}

function isIssueResolved(issue) {
  return Boolean(normalizeIssue(issue).resolved);
}

function latestProjectIssue(project) {
  const issues = (project.issues || []).map(normalizeIssue);
  if (!issues.length) return null;
  const active = issues.filter((issue) => !issue.resolved);
  if (active.length) return active[0];
  return issues[0];
}

function buildIssueFieldOptions(options, selected, placeholder = "값을 선택해 주세요") {
  const selectedValue = String(selected || "");
  return [
    `<option value=""${selectedValue ? "" : " selected"}>${escapeHtml(placeholder)}</option>`,
    ...options.map((option) => `<option value="${escapeAttr(option)}"${option === selectedValue ? " selected" : ""}>${escapeHtml(option)}</option>`),
  ].join("");
}

function mergeAdminFields() {
  const adminByNo = new Map(adminProjects.map((project) => [String(project.projectNo).trim(), project]));
  const existingNos = new Set(projects.map((project) => String(project.projectNo).trim()));
  projects = projects.map((project) => {
    const admin = adminByNo.get(String(project.projectNo).trim());
    if (!admin) return project;
    return {
      ...project,
      progressStatus: admin.progressStatus,
      pm: admin.pm,
      adminMilestone: admin.milestone,
    };
  });
  adminProjects.forEach((admin) => {
    const projectNo = String(admin.projectNo).trim();
    if (existingNos.has(projectNo)) return;
    projects.push(
      normalizeProject({
        id: `admin-${projectNo}`,
        no: projectNo,
        status: admin.progressStatus || "미지정",
        progressStatus: admin.progressStatus || "미지정",
        projectNo,
        name: admin.name,
        contractDate: "",
        dueDate: "",
        openDate: "",
        contractAmount: "",
        balance: admin.balance,
        depositDate: "",
        milestone: admin.milestone,
        adminMilestone: admin.milestone,
        designer: admin.designer,
        publisher: admin.publisher,
        programmer: "",
        pm: admin.pm,
        quoteFileName: "",
        quoteFileData: "",
        clientName: "",
        clientPhone: "",
        clientEmail: "",
        communicationLog: "",
        clientContacts: [],
        communications: [],
        schedules: [],
        hostingType: "일반 웹호스팅",
        hasForeignLanguage: admin.milestone === "외국어작업",
        monthlyCollection: Boolean(admin.monthlyCollection),
        hasLanding: false,
        industry: "",
        issues: [],
      })
    );
    existingNos.add(projectNo);
  });
}


function cloneProjectsForLog(items) {
  return JSON.parse(JSON.stringify(items || []));
}

function syncProjectsPersistSnapshot(source = projects) {
  projectsPersistSnapshot = cloneProjectsForLog(source);
}

function createProjectLogEntry({ action, category, project, target = "", summary = "" }) {
  return {
    action,
    category,
    projectNo: String(project?.projectNo || "").trim(),
    projectName: String(project?.name || "").trim(),
    target,
    summary,
  };
}

function hasLogValue(value) {
  return String(value ?? "").trim() !== "";
}

function projectLogFieldLabel(key) {
  const labels = {
    depositDate: "완료일자",
    milestone: "마일스톤",
    adminMilestone: "마일스톤",
    status: "작업상태",
    progressStatus: "작업상태",
    hasIssue: "이슈",
  };
  return labels[key] || key;
}

function scalarLogSummary(key, beforeValue, afterValue) {
  if (key === "depositDate") {
    const beforeHas = hasLogValue(beforeValue);
    const afterHas = hasLogValue(afterValue);
    if (!beforeHas && afterHas) return "완료일자 등록";
    if (beforeHas && !afterHas) return "완료일자 삭제";
    return "완료일자 수정";
  }
  if (key === "hasIssue") return afterValue ? "이슈 등록" : "이슈 해제";
  const label = projectLogFieldLabel(key);
  const beforeHas = hasLogValue(beforeValue);
  const afterHas = hasLogValue(afterValue);
  if (!beforeHas && afterHas) return `${label} 등록`;
  if (beforeHas && !afterHas) return `${label} 삭제`;
  return `${label} 변경`;
}

function issueLogSummary(previous, current, action) {
  const before = previous ? normalizeIssue(previous) : null;
  const after = current ? normalizeIssue(current) : null;
  const beforeMemo = before ? String(before.memo || "").trim() : "";
  const afterMemo = after ? String(after.memo || "").trim() : "";
  if (action === "등록") return afterMemo ? "이슈 내용 등록" : "이슈 등록";
  if (action === "삭제") return beforeMemo ? "이슈 내용 삭제" : "이슈 삭제";
  if (before && after && before.status !== after.status) return "이슈 상태 변경";
  if (before && after && before.type !== after.type) return "이슈 유형 변경";
  const beforeResolved = before ? Boolean(before.resolved) : false;
  const afterResolved = after ? Boolean(after.resolved) : false;
  if (!beforeResolved && afterResolved) return "이슈 해제";
  if (beforeResolved && !afterResolved) return "이슈 등록";
  if (!beforeMemo && afterMemo) return "이슈 내용 등록";
  if (beforeMemo && !afterMemo) return "이슈 내용 삭제";
  if (beforeMemo !== afterMemo) return "이슈 내용 수정";
  return "이슈 수정";
}

function stableIssueSignature(issue) {
  const normalized = normalizeIssue(issue);
  return JSON.stringify({
    status: normalized.status,
    type: normalized.type,
    memo: normalized.memo,
    date: normalized.date,
    resolved: normalized.resolved,
  });
}

function stableScheduleSignature(entry) {
  const normalized = entry || {};
  return JSON.stringify({
    date: String(normalized.date || ""),
    milestone: String(normalized.milestone || ""),
    staffRole: String(normalized.staffRole || ""),
    staffName: String(normalized.staffName || ""),
    detail: String(normalized.detail || ""),
    completed: Boolean(normalized.completed),
  });
}

function scheduleLogSummary(previous, current, action) {
  if (action === "등록") return "일정 등록";
  if (action === "삭제") return "일정 삭제";
  if (Boolean(previous?.completed) !== Boolean(current?.completed)) {
    return current?.completed ? "일정 완료" : "일정 미완료";
  }
  if (String(previous?.date || "") !== String(current?.date || "")) return "일정 날짜 변경";
  if (String(previous?.milestone || "") !== String(current?.milestone || "")) return "일정 마일스톤 변경";
  if (String(previous?.detail || "") !== String(current?.detail || "")) return "일정 내용 변경";
  if (String(previous?.staffRole || "") !== String(current?.staffRole || "") || String(previous?.staffName || "") !== String(current?.staffName || "")) {
    return "일정 담당자 변경";
  }
  return "일정 수정";
}

function scheduleLogTarget(entry) {
  return [entry?.date, entry?.milestone, entry?.detail].filter(Boolean).join(" · ") || "일정";
}


function buildProjectLogsFromDiff(beforeProjects, afterProjects) {
  const logs = [];
  const beforeMap = new Map((beforeProjects || []).map((project) => [project.id, project]));
  const afterMap = new Map((afterProjects || []).map((project) => [project.id, project]));
  beforeMap.forEach((project, id) => {
    if (!afterMap.has(id)) logs.push(createProjectLogEntry({ action: "삭제", category: "프로젝트", project, summary: "프로젝트 삭제" }));
  });
  afterMap.forEach((project, id) => {
    const previous = beforeMap.get(id);
    if (!previous) {
      logs.push(createProjectLogEntry({ action: "등록", category: "프로젝트", project, summary: "프로젝트 등록" }));
      return;
    }
    ["depositDate", "milestone", "adminMilestone", "status", "progressStatus", "hasIssue"].forEach((key) => {
      if (key === "progressStatus" && String(previous.status ?? "") !== String(project.status ?? "")) return;
      if (String(previous[key] ?? "") === String(project[key] ?? "")) return;
      const summary = scalarLogSummary(key, previous[key], project[key]);
      if (summary) logs.push(createProjectLogEntry({ action: "수정", category: "프로젝트", project, target: projectLogFieldLabel(key), summary }));
    });
    const beforeIssues = new Map((previous.issues || []).map((issue) => [issue.id, issue]));
    const afterIssues = new Map((project.issues || []).map((issue) => [issue.id, issue]));
    beforeIssues.forEach((issue, issueId) => {
      if (!afterIssues.has(issueId)) logs.push(createProjectLogEntry({ action: "삭제", category: "이슈", project, target: "이슈", summary: issueLogSummary(issue, null, "삭제") }));
    });
    afterIssues.forEach((issue, issueId) => {
      const old = beforeIssues.get(issueId);
      if (!old) {
        logs.push(createProjectLogEntry({ action: "등록", category: "이슈", project, target: "이슈", summary: issueLogSummary(null, issue, "등록") }));
        return;
      }
      if (stableIssueSignature(old) !== stableIssueSignature(issue)) {
        logs.push(createProjectLogEntry({ action: "수정", category: "이슈", project, target: "이슈", summary: issueLogSummary(old, issue, "수정") }));
      }
    });
    const beforeSchedules = new Map((previous.schedules || []).map((entry) => [entry.id, entry]));
    const afterSchedules = new Map((project.schedules || []).map((entry) => [entry.id, entry]));
    beforeSchedules.forEach((entry, entryId) => {
      if (!afterSchedules.has(entryId)) {
        logs.push(createProjectLogEntry({ action: "삭제", category: "일정", project, target: scheduleLogTarget(entry), summary: scheduleLogSummary(entry, null, "삭제") }));
      }
    });
    afterSchedules.forEach((entry, entryId) => {
      const old = beforeSchedules.get(entryId);
      if (!old) {
        logs.push(createProjectLogEntry({ action: "등록", category: "일정", project, target: scheduleLogTarget(entry), summary: scheduleLogSummary(null, entry, "등록") }));
        return;
      }
      if (stableScheduleSignature(old) !== stableScheduleSignature(entry)) {
        logs.push(createProjectLogEntry({ action: "수정", category: "일정", project, target: scheduleLogTarget(entry), summary: scheduleLogSummary(old, entry, "수정") }));
      }
    });
  });
  return logs;
}

async function persist() {
  const snapshot = await projectRepository.saveProjects(projects);
  updateStateFromSnapshot(snapshot, { keepSelected: true });
  if (currentView === "projectLogs") {
    projectLogPage = 1;
    await refreshProjectLogs(1);
  }
  syncProjectsPersistSnapshot(projects);
}

function detailAccessibleProjects() {
  if (currentView === "monthly" || currentView === "issues") return monthlyIssueProjectSource();
  if (currentView === "schedule" && canViewAllProjectSchedules()) return projects;
  return accessibleProjects();
}

function selectedProject() {
  if (isCreatingProject && draftProject) return draftProject;
  const visible = detailAccessibleProjects();
  return visible.find((project) => project.id === selectedId) || visible[0] || null;
}

function createEmptyProject() {
  const projectNo = nextProjectNo();
  return {
    id: crypto.randomUUID(),
    no: projects.length + 1,
    status: "",
    progressStatus: "",
    projectNo,
    name: "",
    contractDate: "",
    dueDate: "",
    openDate: "",
    contractAmount: "",
    balance: "",
    industry: "",
    pm: "",
    pmId: "",
    depositDate: "",
    milestone: "",
    designer: "",
    designerId: "",
    publisher: "",
    publisherId: "",
    programmer: "",
    programmerId: "",
    quoteFileName: "",
    quoteFileData: "",
    shortcutUrl: "",
    intranetUrl: "",
    designUrl: "",
    clientName: "",
    clientPhone: "",
    clientEmail: "",
    communicationLog: "",
    clientContacts: [],
    communications: [],
    schedules: [],
    hostingType: "일반 웹호스팅",
    hasForeignLanguage: false,
    monthlyCollection: false,
    hasLanding: false,
    hasIssue: false,
    issues: [],
  };
}

function cancelCreateProject() {
  isCreatingProject = false;
  draftProject = null;
}

function openDetailDropdowns() {
  document.querySelectorAll(".detail-dropdown").forEach((dropdown) => {
    dropdown.setAttribute("open", "");
  });
}

function normalizeMilestoneName(milestone) {
  return String(milestone || "").trim().replace(/\s+/g, "");
}

function isInactiveProgressMilestone(milestone) {
  const value = normalizeMilestoneName(milestone);
  return INACTIVE_PROGRESS_MILESTONES.some((item) => normalizeMilestoneName(item) === value);
}

function progressProjects() {
  return accessibleProjects().filter((project) => !isInactiveProgressMilestone(projectMilestone(project)));
}

function activeProjects() {
  return progressProjects();
}

function isAdmin() {
  return currentUser?.role === "admin";
}

function isTeamLead() {
  return currentUser?.role === "team_lead";
}

function roleLabel(role) {
  if (role === "admin") return "관리자";
  if (role === "team_lead") return "팀장";
  return "일반";
}

function roleBadgeClass(role) {
  return role === "admin" ? "admin" : "user";
}

function currentDepartment() {
  return String(currentUser?.department || "").trim().toLowerCase();
}

function normalizeDepartmentKey(value) {
  const department = String(value || "").trim().toLowerCase();
  const aliases = {
    "디자이너": "디자인",
    "퍼블리셔": "퍼블리싱",
    "프로그래머": "프로그램",
    "개발": "프로그램",
    "개발자": "프로그램",
  };
  return aliases[department] || department;
}

function isDepartment(...names) {
  const department = normalizeDepartmentKey(currentDepartment());
  return names.map((name) => normalizeDepartmentKey(name)).includes(department);
}

function canViewAllProjects() {
  return isAdmin() || isTeamLead() || isDepartment("경영관리", "영업", "pm");
}

function canCreateProject() {
  return isAdmin() || isDepartment("영업");
}

function canEditProjectDetail() {
  return isAdmin() || isTeamLead() || isDepartment("pm");
}

function canEditProjectActivity() {
  return canEditProjectDetail() || isDepartment("영업");
}

function canEditProjectIssues() {
  return isAdmin() || isDepartment("영업", "pm", "디자인", "디자이너", "퍼블리싱", "퍼블리셔", "프로그램", "프로그래머");
}

function canEditProjectCommunications() {
  return isAdmin() || isDepartment("영업", "pm");
}

function canDeleteProjectActivityEntries() {
  return isAdmin();
}

function canManageProjectQuote() {
  return isAdmin() || isDepartment("영업", "경영관리");
}

function canViewMonthlyAndIssues() {
  return isAdmin() || isTeamLead() || isDepartment("pm");
}

function canViewAllProjectSchedules() {
  return isAdmin() || isTeamLead();
}

function canManageAllProjectSchedules() {
  return isAdmin();
}

function isProjectWorkerDepartment() {
  return isDepartment("디자인", "디자이너", "퍼블리싱", "퍼블리셔", "프로그램", "프로그래머");
}

function canUseAssignedProjectSchedules() {
  return isDepartment("pm") || isProjectWorkerDepartment();
}

function usesFullScheduleDialog() {
  return isAdmin() || isDepartment("pm");
}

function canCreateProjectSchedule(project = null) {
  if (!currentUser) return false;
  if (canManageAllProjectSchedules()) return true;
  return Boolean(project && canUseAssignedProjectSchedules() && isAssignedProject(project));
}

function scheduleEntryOwnedByCurrentUser(entry) {
  if (!currentUser || !entry) return false;
  const userId = assignedProjectUserId().toLowerCase();
  const userName = assignedProjectUserName().toLowerCase();
  const ownerId = String(entry.createdById || "").trim().toLowerCase();
  const ownerName = String(entry.createdByName || "").trim().toLowerCase();
  const staffName = String(entry.staffName || "").trim().toLowerCase();
  return Boolean((userId && ownerId === userId) || (userName && (ownerName === userName || (!ownerId && staffName === userName))));
}

function canViewProjectScheduleEntry(entry) {
  if (!currentUser) return false;
  if (canViewAllProjectSchedules()) return true;
  if (canUseAssignedProjectSchedules()) {
    const project = projects.find((item) => item.id === entry?.projectId || (entry?.projectNo && String(item.projectNo || "") === String(entry.projectNo)));
    return project ? isAssignedProject(project) : scheduleEntryOwnedByCurrentUser(entry);
  }
  return false;
}

function canManageProjectScheduleEntry(project, entry = null) {
  if (!currentUser) return false;
  if (canManageAllProjectSchedules()) return true;
  if (!project || !canUseAssignedProjectSchedules() || !isAssignedProject(project)) return false;
  return entry ? scheduleEntryOwnedByCurrentUser(entry) : true;
}

function canViewDashboardProjectMetrics() {
  return isAdmin() || isDepartment("pm");
}

function assignedProjectUserName() {
  return String(currentUser?.name || "").trim();
}

function assignedProjectUserId() {
  return String(currentUser?.id || "").trim();
}

function projectStaffMatches(project, nameField, idField) {
  const userId = assignedProjectUserId().toLowerCase();
  const userName = assignedProjectUserName().toLowerCase();
  const assignedId = String(project?.[idField] || "").trim().toLowerCase();
  const assignedName = String(project?.[nameField] || "").trim().toLowerCase();
  return Boolean((userId && assignedId === userId) || (userName && assignedName === userName));
}

const PROJECT_STAFF_ASSIGNMENTS = [
  { nameField: "pm", idField: "pmId", departments: ["pm"] },
  { nameField: "designer", idField: "designerId", departments: ["디자인", "디자이너"] },
  { nameField: "publisher", idField: "publisherId", departments: ["퍼블리싱", "퍼블리셔"] },
  { nameField: "programmer", idField: "programmerId", departments: ["프로그램", "프로그래머"] },
];

const PROJECT_COMPLETION_STAGES = [
  { key: "design_worker", label: "담당자 디자인 완료", actor: "worker", departments: ["디자인", "디자이너"], nameField: "designer", idField: "designerId" },
  { key: "design_lead", label: "팀장 디자인 완료", actor: "lead", departments: ["디자인", "디자이너"] },
  { key: "design_pm", label: "PM 디자인 완료", actor: "pm", departments: ["pm"], nameField: "pm", idField: "pmId" },
  { key: "publishing_worker", label: "담당자 퍼블리싱 완료", actor: "worker", departments: ["퍼블리싱", "퍼블리셔"], nameField: "publisher", idField: "publisherId" },
  { key: "publishing_lead", label: "팀장 퍼블리싱 완료", actor: "lead", departments: ["퍼블리싱", "퍼블리셔"] },
  { key: "publishing_pm", label: "PM 퍼블리싱 완료", actor: "pm", departments: ["pm"], nameField: "pm", idField: "pmId" },
  { key: "program_worker", label: "담당자 프로그램 완료", actor: "worker", departments: ["프로그램", "프로그래머"], nameField: "programmer", idField: "programmerId" },
  { key: "program_lead", label: "팀장 프로그램 완료", actor: "lead", departments: ["프로그램", "프로그래머"] },
  { key: "program_pm", label: "PM 프로그램 완료", actor: "pm", departments: ["pm"], nameField: "pm", idField: "pmId" },
];

function normalizeProjectCompletionFlow(flow = {}) {
  const allowed = new Set(PROJECT_COMPLETION_STAGES.map((stage) => stage.key));
  const completed = Array.isArray(flow?.completed) ? flow.completed.filter((key) => allowed.has(key)) : [];
  const history = Array.isArray(flow?.history) ? flow.history : [];
  return {
    completed: [...new Set(completed)],
    pendingType: String(flow?.pendingType || ""),
    hideApproval: Boolean(flow?.hideApproval),
    history: history.map((entry) => ({
      id: String(entry?.id || crypto.randomUUID()),
      stage: String(entry?.stage || ""),
      label: String(entry?.label || ""),
      userId: String(entry?.userId || ""),
      userName: String(entry?.userName || ""),
      at: String(entry?.at || ""),
      memo: String(entry?.memo || ""),
      action: String(entry?.action || "approve"),
      reason: String(entry?.reason || ""),
      completionType: String(entry?.completionType || ""),
    })),
  };
}

function projectCompletionStage(project) {
  const flow = normalizeProjectCompletionFlow(project?.completionFlow);
  const completed = new Set(flow.completed);
  return PROJECT_COMPLETION_STAGES.find((stage) => !completed.has(stage.key)) || null;
}

function projectCompletionDone(project, ...stageKeys) {
  const completed = new Set(normalizeProjectCompletionFlow(project?.completionFlow).completed);
  return stageKeys.every((key) => completed.has(key));
}

function projectCompletionActorName(project, stage) {
  if (!stage) return "-";
  const key = String(stage.key || "");
  if (key.startsWith("design_")) return project?.designer || "-";
  if (key.startsWith("publishing_")) return project?.publisher || "-";
  if (key.startsWith("program_")) return project?.programmer || "-";
  if (stage.actor === "worker" || stage.actor === "pm") return project?.[stage.nameField] || "-";
  return "-";
}

function lastProjectCompletionEntry(project) {
  const history = normalizeProjectCompletionFlow(project?.completionFlow).history;
  return history.length ? history[history.length - 1] : null;
}

function userAlreadyHandledLatestCompletion(project) {
  const latest = lastProjectCompletionEntry(project);
  return Boolean(currentUser?.id && latest?.userId && String(latest.userId) === String(currentUser.id));
}

function userCanActProjectCompletion(project, stage = projectCompletionStage(project)) {
  if (!currentUser || !project || !stage) return false;
  if (isAdmin()) return true;
  if (stage.actor === "lead") return isTeamLead() && stage.departments.some((department) => isDepartment(department));
  if (stage.actor === "pm") return isDepartment("pm") && (isTeamLead() || projectStaffMatches(project, "pm", "pmId"));
  if (stage.actor === "worker") return projectStaffMatches(project, stage.nameField, stage.idField);
  return false;
}

function projectCompletionSource() {
  const map = new Map();
  [...projects, ...assignmentProjects, ...scheduleProjects].forEach((project) => {
    if (project?.id && !map.has(project.id)) map.set(project.id, project);
  });
  return [...map.values()];
}

function projectCompletionRowsForCurrentUser() {
  return projectCompletionSource().filter((project) => {
    const flow = normalizeProjectCompletionFlow(project?.completionFlow);
    if (flow.hideApproval) return false;
    const stage = projectCompletionStage(project);
    return stage?.actor !== "worker" && userCanActProjectCompletion(project, stage);
  });
}

function projectCompletionCount() {
  return projectCompletionRowsForCurrentUser().length;
}

function userMatchesAnyDepartment(user, departments) {
  const department = normalizeDepartmentKey(user?.department || "");
  return departments.map((name) => normalizeDepartmentKey(name)).includes(department);
}

function findStaffUserByName(name, departments) {
  const value = String(name || "").trim().toLowerCase();
  if (!value) return null;
  const users = projectRepository.getUsers?.() || [];
  return (
    users.find((user) => String(user.name || "").trim().toLowerCase() === value && userMatchesAnyDepartment(user, departments)) ||
    (String(currentUser?.name || "").trim().toLowerCase() === value && userMatchesAnyDepartment(currentUser, departments) ? currentUser : null)
  );
}

function applyProjectStaffIds(project) {
  PROJECT_STAFF_ASSIGNMENTS.forEach(({ nameField, idField, departments }) => {
    const staff = findStaffUserByName(project[nameField], departments);
    if (staff?.id) project[idField] = staff.id;
  });
  return project;
}

function isAssignedProject(project) {
  if (!assignedProjectUserId() && !assignedProjectUserName()) return false;
  if (isDepartment("디자인", "디자이너")) return projectStaffMatches(project, "designer", "designerId");
  if (isDepartment("퍼블리싱", "퍼블리셔")) return projectStaffMatches(project, "publisher", "publisherId");
  if (isDepartment("프로그램", "프로그래머")) return projectStaffMatches(project, "programmer", "programmerId");
  if (isDepartment("pm")) return projectStaffMatches(project, "pm", "pmId");
  return false;
}

function canViewAssignedProjectSchedules() {
  return canUseAssignedProjectSchedules();
}

function projectScheduleVisibleProjects() {
  if (!currentUser) return accessibleProjects();
  if (canViewAllProjectSchedules()) return isAdmin() ? projects : scheduleProjects;
  if (canViewAssignedProjectSchedules()) return projects.filter(isAssignedProject);
  return [];
}

function isReadOnlyMode() {
  return !currentUser;
}

function requireWritableAction() {
  if (!isReadOnlyMode() && (canEditProjectDetail() || canEditProjectActivity() || canEditProjectIssues() || canEditProjectCommunications() || canManageProjectQuote() || (isCreatingProject && canCreateProject()))) return true;
  alert(currentUser ? "현재 계정은 프로젝트를 수정할 권한이 없습니다." : "비로그인 상태에서는 읽기 전용으로만 볼 수 있습니다. 수정하려면 로그인해 주세요.");
  return false;
}

function isApprovedUser() {
  return Boolean(currentUser) && currentUser.approvalStatus === "활성화";
}

function currentPmName() {
  return String(currentUser?.name || "").trim();
}

function accessibleProjects() {
  if (!currentUser || canViewAllProjects()) return projects;
  return projects.filter(isAssignedProject);
}

function canViewProjectCompletionApproval() {
  return Boolean(currentUser) && (isAdmin() || !isDepartment("영업"));
}

function canAccessView(view) {
  if (view === "members" || view === "departments" || view === "adminSettings" || view === "loginLogs" || view === "projectLogs") return isAdmin();
  if (view === "leaveApprovals") return isAdmin();
  if (view === "projectCompletionApproval") return canViewProjectCompletionApproval();
  if (view === "projectAssignment") return isAdmin() || isTeamLead();
  if (view === "monthly" || view === "issues") return canViewMonthlyAndIssues();
  if (view === "leaveManagement") return Boolean(currentUser);
  return true;
}

function activateViewPanel(view) {
  document.querySelectorAll(".view").forEach((panel) => panel.classList.remove("active"));
  $(`${view}View`)?.classList.add("active");
  document.querySelectorAll(".nav-item").forEach((item) => {
    if (item.classList.contains("nav-parent")) {
      item.classList.remove("active");
      return;
    }
    item.classList.toggle("active", item.dataset.view === view);
  });
}

function saveUiSessionState() {
  try {
    sessionStorage.setItem(
      UI_SESSION_STATE_KEY,
      JSON.stringify({
        view: currentView,
        selectedId,
        detailOpen: document.body.classList.contains("detail-open"),
        scheduleDetailOpen: document.body.classList.contains("schedule-detail-open"),
      })
    );
  } catch (error) {
    console.warn("UI state could not be saved.", error);
  }
}

function restoreUiSessionState() {
  let state = null;
  try {
    state = JSON.parse(sessionStorage.getItem(UI_SESSION_STATE_KEY) || "null");
  } catch (error) {
    state = null;
  }
  const view = state?.view && canAccessView(state.view) ? state.view : "dashboard";
  currentView = view;

  const visibleProjects = accessibleProjects();
  const restoredProject = visibleProjects.find((project) => project.id === state?.selectedId);
  selectedId = restoredProject?.id || visibleProjects[0]?.id || null;

  document.body.classList.remove("detail-open", "schedule-detail-open");
  if (state?.detailOpen && restoredProject) {
    document.body.classList.add("detail-open");
    if (state?.scheduleDetailOpen) document.body.classList.add("schedule-detail-open");
  }
  activateViewPanel(currentView);
}

function updateProjectCompletionNavCount() {
  const item = document.querySelector('[data-view="projectCompletionApproval"]');
  if (!item) return;
  if (!item.dataset.originalLabel) item.dataset.originalLabel = item.textContent.trim();
  const count = currentUser ? projectCompletionCount() : 0;
  item.textContent = count > 0 ? `${item.dataset.originalLabel} (${count})` : item.dataset.originalLabel;
}

function updateProjectAssignmentNavCount() {
  const item = document.querySelector('[data-view="projectAssignment"]');
  if (!item) return;
  if (!item.dataset.originalLabel) item.dataset.originalLabel = item.textContent.trim();
  const count = projectAssignmentCount();
  item.textContent = count > 0 ? `${item.dataset.originalLabel} (${count})` : item.dataset.originalLabel;
}

function updateNavAccess() {
  document.querySelectorAll(".admin-only").forEach((item) => {
    const view = item.dataset.view || "";
    const visible = view === "projectAssignment" ? isAdmin() || isTeamLead() : view === "projectCompletionApproval" ? canViewProjectCompletionApproval() : isAdmin();
    item.classList.toggle("hidden", !visible);
  });
  const subtleLockedViews = new Set(["leaveApprovals", "departments", "members"]);
  document.querySelectorAll("[data-auth-menu]").forEach((item) => {
    const authMenu = item.dataset.authMenu || "";
    const isParent = item.classList.contains("nav-parent");
    const showLockedMenu = !currentUser && (authMenu === "attendance" || authMenu === "basic");
    const isAdminOnly = item.classList.contains("admin-only");
    const isAdminSection = authMenu === "basic";
    const shouldShow = isAdminSection && currentUser && !isAdmin() ? false : isAdminOnly && !isAdmin() ? false : currentUser || showLockedMenu;
    item.classList.toggle("hidden", !shouldShow);
    if (!item.dataset.originalLabel) item.dataset.originalLabel = item.textContent.trim();
    const isSubtleLocked = showLockedMenu && !isParent && subtleLockedViews.has(item.dataset.view || "");
    item.textContent = showLockedMenu && !isSubtleLocked ? `🔒 ${item.dataset.originalLabel}` : item.dataset.originalLabel;
    item.classList.toggle("is-locked-muted", Boolean(isSubtleLocked));
  });
  document.querySelectorAll('[data-view="loginLogs"], [data-view="projectLogs"]').forEach((item) => {
    item.classList.toggle("hidden", !isAdmin());
  });
  document.querySelectorAll('[data-view="monthly"], [data-view="issues"]').forEach((item) => {
    item.classList.toggle("hidden", !canViewMonthlyAndIssues());
  });
  if (!isAdmin() && (currentView === "members" || currentView === "departments" || currentView === "adminSettings" || currentView === "loginLogs" || currentView === "projectLogs" || currentView === "leaveApprovals")) {
    switchView("dashboard");
  }
  if (!canViewProjectCompletionApproval() && currentView === "projectCompletionApproval") switchView("dashboard");
  if (!isAdmin() && !isTeamLead() && currentView === "projectAssignment") switchView("dashboard");
  if (!canViewMonthlyAndIssues() && (currentView === "monthly" || currentView === "issues")) switchView("dashboard");
  if (!currentUser && currentView === "leaveManagement") switchView("dashboard");
}

function dashboardMilestones() {
  return [
    "자료요청중",
    "화면설계중",
    "메인시안중",
    "서브시안중",
    "상세디자인",
    "퍼블리싱중",
    "프로그램중",
    "통합테스트",
    "외국어작업",
    "고객검수중",
    "오픈안내함",
    "연락두절",
    "작업중단",
    "작업중단-고객요청",
    "내용증명",
    "법정다툼",
    "프로젝트종료",
  ];
}

function workStatusOptions() {
  return [
    "작업중",
    "피드백 대기",
    "피드백 지연",
    "작업대기 - 고객요청",
    "입금대기",
    "입금지연",
    "오픈대기",
    "오픈지연",
    "오픈 전 - 추가작업",
    "오픈 후 - 추가작업",
    "작업중단",
    "계약해지",
    "종결",
  ];
}

function workStatusBadgeClass(status) {
  const key = String(status || "")
    .replace(/\s+/g, "")
    .trim();
  if (!key || key === "미지정") return "badge-status-muted";
  if (key === "진행중" || key === "작업중") return "";
  if (key.includes("피드백") && (key.includes("지연") || key.includes("대기"))) return "badge-status-feedback";
  if (key.includes("입금") && (key.includes("지연") || key.includes("대기"))) return "badge-status-deposit";
  if (key.includes("오픈") && (key.includes("지연") || key.includes("대기"))) return "badge-status-open";
  return "badge-status-muted";
}

function dashboardVisibleMilestones() {
  return [
    "자료요청중",
    "화면설계중",
    "메인시안중",
    "서브시안중",
    "상세디자인",
    "퍼블리싱중",
    "프로그램중",
    "통합테스트",
    "외국어작업",
    "고객검수중",
    "오픈안내함",
  ];
}

function formatDate(value) {
  return value || "-";
}

function parseProjectDateValue(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  const normalized = text.includes("T") ? text : text.replace(" ", "T");
  const date = new Date(normalized);
  if (!Number.isNaN(date.getTime())) return date;
  const parts = parseDateParts(text.slice(0, 10));
  if (!parts) return null;
  return new Date(parts.year, parts.month - 1, parts.day);
}

function projectElapsedDays(startValue, endValue) {
  const start = parseProjectDateValue(startValue);
  const end = parseProjectDateValue(endValue);
  if (!start || !end) return null;
  const startDay = Date.UTC(start.getFullYear(), start.getMonth(), start.getDate());
  const endDay = Date.UTC(end.getFullYear(), end.getMonth(), end.getDate());
  const diff = Math.floor((endDay - startDay) / 86400000) + 1;
  return diff > 0 ? diff : 1;
}

function formatMoney(value) {
  if (value === null || value === undefined || value === "") return "-";
  return `${Number(value).toLocaleString("ko-KR")}만원`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("\n", " ");
}

function syncSidebarWidthToClock() {
  const clock = $("clock");
  const topbar = document.querySelector(".topbar");
  if (!clock || !topbar || document.body.classList.contains("sidebar-collapsed")) return;
  const padLeft = parseFloat(getComputedStyle(topbar).paddingLeft) || 0;
  const width = Math.ceil(clock.getBoundingClientRect().width + padLeft);
  if (width > 0) document.documentElement.style.setProperty("--sidebar-width", `${width}px`);
}

function renderClock() {
  if (!$("clock")) return;
  const now = new Date();
  const text = new Intl.DateTimeFormat("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(now);
  $("clock").textContent = text;
  syncSidebarWidthToClock();
}

function switchView(view) {
  if (!canAccessView(view)) view = "dashboard";
  if (view !== "projects") cancelCreateProject();
  currentView = view;
  document.body.classList.remove("detail-open", "schedule-detail-open");
  activateViewPanel(view);
  renderAll(false);
  saveUiSessionState();
}

function projectDisplayStatus(project) {
  return project.progressStatus || project.status || "미지정";
}

function projectMilestone(project) {
  return project.adminMilestone || project.milestone || "";
}

function buildProjectSearchHaystack(project) {
  const parts = [
    project.name,
    project.projectNo,
    project.status,
    project.progressStatus,
    project.milestone,
    project.adminMilestone,
    projectDisplayStatus(project),
    projectMilestone(project),
    project.industry,
    project.contractDate,
    project.dueDate,
    project.openDate,
    project.depositDate,
    project.contractAmount,
    project.balance,
    project.pm,
    project.designer,
    project.publisher,
    project.programmer,
    project.shortcutUrl,
    project.intranetUrl,
    project.designUrl,
    project.hostingType,
    project.quoteFileName,
    project.clientName,
    project.clientPhone,
    project.clientEmail,
    project.communicationLog,
  ];

  if (project.hasForeignLanguage) parts.push("외국어", "다국어");
  if (project.hasLanding) parts.push("랜딩");
  else if (project.hasLanding === false) parts.push("일반형");
  if (project.monthlyCollection) parts.push("당월수금");
  if (project.hasIssue) parts.push("이슈");
  if (project.hostingType === "단독서버") parts.push("단독서버");
  if (project.hostingType === "일반 웹호스팅") parts.push("일반 웹호스팅");

  (project.clientContacts || []).forEach((contact) => {
    parts.push(contact.name, contact.companyPhone, contact.personalPhone, contact.email);
  });
  (project.communications || []).forEach((entry) => {
    parts.push(entry.date, entry.memo);
  });
  (project.issues || []).forEach((issue) => {
    const normalized = normalizeIssue(issue);
    parts.push(normalized.status, normalized.type, normalized.memo);
  });

  return parts
    .filter((value) => value != null && String(value).trim() !== "")
    .join(" ")
    .toLowerCase();
}

function digitsOnly(value) {
  return String(value || "").replace(/\D/g, "");
}

function formatClientPhone(value) {
  const digits = digitsOnly(value).slice(0, 11);
  if (digits.length <= 3) return digits;
  if (digits.length === 10) return `${digits.slice(0, 2)}-${digits.slice(2, 6)}-${digits.slice(6)}`;
  if (digits.length >= 11) return `${digits.slice(0, 3)}-${digits.slice(3, 7)}-${digits.slice(7)}`;
  if (digits.length <= 7) return `${digits.slice(0, 3)}-${digits.slice(3)}`;
  return `${digits.slice(0, 3)}-${digits.slice(3, 7)}-${digits.slice(7)}`;
}

function bindClientPhoneInput(input) {
  if (!input) return;
  input.addEventListener("input", () => {
    input.value = formatClientPhone(input.value);
  });
  input.addEventListener("blur", () => {
    input.value = formatClientPhone(input.value);
  });
}

function matchedClientContacts(project) {
  const query = valueOf("searchInput").trim();
  const queryDigits = digitsOnly(query);
  if (!queryDigits) return [];

  return (project.clientContacts || [])
    .map((contact) => {
      const phones = [contact.companyPhone, contact.personalPhone]
        .map((phone) => String(phone || "").trim())
        .filter(Boolean);
      const matchedPhones = phones.filter((phone) => digitsOnly(phone).includes(queryDigits));
      return matchedPhones.length
        ? {
            name: contact.name || "담당자",
            phones: matchedPhones,
          }
        : null;
    })
    .filter(Boolean);
}

function renderMatchedClientContacts(project) {
  const matches = matchedClientContacts(project);
  if (!matches.length) return "";
  return `<div class="project-contact-preview">${matches
    .map(
      (contact) =>
        `<div class="project-contact-line-matched">${escapeHtml(contact.name)} · ${escapeHtml(contact.phones.join(" / "))}</div>`
    )
    .join("")}</div>`;
}

function projectCompletionEntryAt(project, stageKey) {
  const completed = new Set(normalizeProjectCompletionFlow(project?.completionFlow).completed);
  if (!completed.has(stageKey)) return null;
  return (
    normalizeProjectCompletionFlow(project?.completionFlow).history
      .filter((entry) => String(entry?.action || "approve") === "approve" && String(entry?.stage || "") === stageKey)
      .sort((a, b) => String(b.at || "").localeCompare(String(a.at || "")))[0] || null
  );
}

function projectPartDurationBadge(project, part) {
  const config = {
    pm: { startStage: "program_lead", endStage: "program_pm" },
    designer: { assignedAt: "designerAssignedAt", endStage: "design_lead", fallbackStartStage: "design_worker" },
    publisher: { assignedAt: "publisherAssignedAt", endStage: "publishing_lead", fallbackStartStage: "design_pm", secondaryFallbackStartStage: "publishing_worker" },
    programmer: { assignedAt: "programmerAssignedAt", endStage: "program_lead", fallbackStartStage: "publishing_pm", secondaryFallbackStartStage: "program_worker" },
  }[part];
  if (!config) return "";
  const completedEntry = projectCompletionEntryAt(project, config.endStage);
  if (!completedEntry?.at) return "";
  const fallbackStart = config.startStage
    ? projectCompletionEntryAt(project, config.startStage)?.at
    : projectCompletionEntryAt(project, config.fallbackStartStage)?.at || projectCompletionEntryAt(project, config.secondaryFallbackStartStage)?.at || "";
  const assignedAt = config.assignedAt ? project?.[config.assignedAt] : "";
  const startAt = assignedAt || fallbackStart;
  const days = projectElapsedDays(startAt, completedEntry.at);
  if (!days) return "";
  const startLabel = assignedAt ? "배정일" : "시작일";
  const endLabel = part === "pm" ? "PM 완료일" : "팀장 완료일";
  const title = `${startLabel} ${formatDate(String(startAt).slice(0, 10))} · ${endLabel} ${formatDate(String(completedEntry.at).slice(0, 10))}`;
  return `<span class="staff-duration-badge" title="${escapeAttr(title)}">${days.toLocaleString("ko-KR")}일</span>`;
}

function projectStaffCell(project, field, part = "") {
  const name = String(project?.[field] || "").trim();
  const badge = shouldShowStaffDurationBadges() ? projectPartDurationBadge(project, part) : "";
  return `<div class="project-staff-cell"><span>${escapeHtml(name || "-")}</span>${badge}</div>`;
}

function getSelectedMilestoneFilters() {
  const menu = $("milestoneFilterMenu");
  if (!menu) return selectedMilestoneFilters;
  return [...menu.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
}

function updateMilestoneFilterLabel() {
  const selected = getSelectedMilestoneFilters();
  selectedMilestoneFilters = selected;
  const label = $("milestoneFilterLabel");
  if (!label) return;
  if (!selected.length) {
    label.textContent = "전체 마일스톤";
    return;
  }
  if (selected.length === 1) {
    label.textContent = selected[0];
    return;
  }
  label.textContent = `마일스톤 ${selected.length}개`;
}

function getSelectedStatusFilters() {
  const menu = $("statusFilterMenu");
  if (!menu) return selectedStatusFilters;
  return [...menu.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
}

function updateStatusFilterLabel() {
  const selected = getSelectedStatusFilters();
  selectedStatusFilters = selected;
  const label = $("statusFilterLabel");
  if (!label) return;
  if (!selected.length) {
    label.textContent = "전체 작업상태";
    return;
  }
  if (selected.length === 1) {
    label.textContent = selected[0];
    return;
  }
  label.textContent = `작업상태 ${selected.length}개`;
}

const PROJECT_OPTION_FILTERS = [
  { key: "foreign", label: "다국어 여부" },
  { key: "landing", label: "랜딩 유무" },
  { key: "designUrl", label: "화면설계 URL 유무" },
  { key: "excludeClosed", label: "종료 건 제외" },
  { key: "workSchedule", label: "작업일정" },
];

function getSelectedProjectOptionFilters() {
  const menu = $("projectOptionFilterMenu");
  if (!menu) return selectedProjectOptionFilters;
  return [...menu.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
}

function updateProjectOptionFilterLabel() {
  const selected = getSelectedProjectOptionFilters();
  selectedProjectOptionFilters = selected;
  const label = $("projectOptionFilterLabel");
  if (!label) return;
  if (!selected.length) {
    label.textContent = "상세 조건";
    return;
  }
  if (selected.length === 1) {
    label.textContent = PROJECT_OPTION_FILTERS.find((option) => option.key === selected[0])?.label || "상세 조건";
    return;
  }
  label.textContent = `상세 조건 ${selected.length}개`;
}

function hasProjectOptionFilter(key) {
  return selectedProjectOptionFilters.includes(key);
}

function shouldShowStaffDurationBadges() {
  return hasProjectOptionFilter("workSchedule");
}

function setMilestoneFilterOpen(open) {
  const wrap = $("milestoneFilterWrap");
  const toggle = $("milestoneFilterToggle");
  if (!wrap || !toggle) return;
  wrap.classList.toggle("open", open);
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    setStatusFilterOpen(false);
    setProjectOptionFilterOpen(false);
  }
}

function setStatusFilterOpen(open) {
  const wrap = $("statusFilterWrap");
  const toggle = $("statusFilterToggle");
  if (!wrap || !toggle) return;
  wrap.classList.toggle("open", open);
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    $("milestoneFilterWrap")?.classList.remove("open");
    $("milestoneFilterToggle")?.setAttribute("aria-expanded", "false");
    setProjectOptionFilterOpen(false);
  }
}

function setProjectOptionFilterOpen(open) {
  const wrap = $("projectOptionFilterWrap");
  const toggle = $("projectOptionFilterToggle");
  if (!wrap || !toggle) return;
  wrap.classList.toggle("open", open);
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    setMilestoneFilterOpen(false);
    setStatusFilterOpen(false);
  }
}

function closeListFilterMenus() {
  setMilestoneFilterOpen(false);
  $("statusFilterWrap")?.classList.remove("open");
  $("statusFilterToggle")?.setAttribute("aria-expanded", "false");
  $("projectOptionFilterWrap")?.classList.remove("open");
  $("projectOptionFilterToggle")?.setAttribute("aria-expanded", "false");
}

function resetProjectListFilters() {
  selectedMilestoneFilters = [];
  selectedStatusFilters = [];
  selectedProjectOptionFilters = ["excludeClosed"];
  progressStatusFilter = "";
  milestoneFilter = "";
  setValue("searchInput", "");
  setValue("pmFilter", "");
  closeListFilterMenus();
}

function openProjectsList(options = {}) {
  const { resetFilters = true } = options;
  if (resetFilters) resetProjectListFilters();
  switchView("projects");
  renderFilters();
  renderRows();
}

function applyDashboardMilestoneFilter(milestone) {
  selectedMilestoneFilters = milestone ? [milestone] : [];
  selectedStatusFilters = [];
  selectedProjectOptionFilters = [];
  progressStatusFilter = "";
  milestoneFilter = "";
  setValue("searchInput", "");
  setValue("pmFilter", "");
  closeListFilterMenus();
  switchView("projects");
  renderFilters();
  renderRows();
}

function uniqueStaffNames(field) {
  return [
    ...new Set(accessibleProjects().map((project) => String(project[field] || "").trim()).filter(Boolean)),
  ].sort((a, b) => a.localeCompare(b, "ko"));
}

function renderStaffFilter(id, field, allLabel) {
  const select = $(id);
  if (!select) return;
  const current = select.value;
  const names = uniqueStaffNames(field);
  select.innerHTML =
    `<option value="">${escapeHtml(allLabel)}</option>` +
    names.map((name) => `<option value="${escapeAttr(name)}">${escapeHtml(name)}</option>`).join("");
  select.value = names.includes(current) ? current : "";
  select.disabled = false;
}

function filteredProjects() {
  const query = valueOf("searchInput").trim().toLowerCase();
  const milestones = getSelectedMilestoneFilters();
  const statuses = getSelectedStatusFilters();
  const optionFilters = getSelectedProjectOptionFilters();
  const pm = valueOf("pmFilter").trim();
  const foreignOnly = optionFilters.includes("foreign");
  const landingOnly = optionFilters.includes("landing");
  const designOnly = optionFilters.includes("designUrl");
  const excludeClosed = optionFilters.includes("excludeClosed");

  return accessibleProjects().filter((project) => {
    const haystack = buildProjectSearchHaystack(project);

    const displayStatus = projectDisplayStatus(project);
    const milestone = projectMilestone(project);
    const hasDesignUrl = Boolean(String(project.designUrl || "").trim());

    return (
      (!query || haystack.includes(query)) &&
      (!pm || String(project.pm || "").trim() === pm) &&
      (!milestones.length ||
        milestones.includes(milestone) ||
        (milestones.includes("미지정") && !milestone)) &&
      (!statuses.length || statuses.includes(displayStatus) || statuses.includes(project.status)) &&
      (!progressStatusFilter || project.progressStatus === progressStatusFilter) &&
      (!milestoneFilter || milestone === milestoneFilter) &&
      (!foreignOnly || project.hasForeignLanguage) &&
      (!landingOnly || project.hasLanding) &&
      (!designOnly || hasDesignUrl) &&
      (!excludeClosed || (!CLOSED_WORK_STATUSES.includes(displayStatus) && !CLOSED_MILESTONES.includes(milestone)))
    );
  });
}

function renderFilters() {
  renderStaffFilter("pmFilter", "pm", "전체 PM");

  const milestones = [
    ...new Set([
      ...dashboardMilestones(),
      ...accessibleProjects().map((project) => projectMilestone(project)).filter(Boolean),
      ...selectedMilestoneFilters,
    ]),
  ];
  const selectedMilestones = new Set(selectedMilestoneFilters.filter((milestone) => milestones.includes(milestone)));
  if ($("milestoneFilterMenu")) {
    $("milestoneFilterMenu").innerHTML = milestones
      .map(
        (milestone) => `
          <label class="multi-select-option">
            <input type="checkbox" value="${escapeAttr(milestone)}" ${selectedMilestones.has(milestone) ? "checked" : ""} />
            <span>${escapeHtml(milestone)}</span>
          </label>
        `
      )
      .join("");
    updateMilestoneFilterLabel();
  }

  const statuses = [
    ...new Set([
      ...workStatusOptions(),
      ...accessibleProjects().flatMap((project) => [project.progressStatus, project.status]).filter(Boolean),
    ]),
  ];
  const selectedStatuses = new Set(selectedStatusFilters.filter((status) => statuses.includes(status)));
  if ($("statusFilterMenu")) {
    $("statusFilterMenu").innerHTML = statuses
      .map(
        (status) => `
          <label class="multi-select-option">
            <input type="checkbox" value="${escapeAttr(status)}" ${selectedStatuses.has(status) ? "checked" : ""} />
            <span>${escapeHtml(status)}</span>
          </label>
        `
      )
      .join("");
    updateStatusFilterLabel();
  }

  const selectedOptions = new Set(selectedProjectOptionFilters);
  if ($("projectOptionFilterMenu")) {
    $("projectOptionFilterMenu").innerHTML = PROJECT_OPTION_FILTERS.map(
      (option) => `
        <label class="multi-select-option">
          <input type="checkbox" value="${escapeAttr(option.key)}" ${selectedOptions.has(option.key) ? "checked" : ""} />
          <span>${escapeHtml(option.label)}</span>
        </label>
      `
    ).join("");
    updateProjectOptionFilterLabel();
  }

  if ($("statusList")) $("statusList").innerHTML = workStatusOptions().map((status) => `<option value="${escapeHtml(status)}"></option>`).join("");
  if ($("milestoneList")) $("milestoneList").innerHTML = dashboardMilestones().map((milestone) => `<option value="${escapeHtml(milestone)}"></option>`).join("");
  if ($("status")) $("status").innerHTML = '<option value=""></option>' + workStatusOptions().map((status) => `<option value="${escapeHtml(status)}">${escapeHtml(status)}</option>`).join("");
  if ($("milestone")) $("milestone").innerHTML = '<option value=""></option>' + dashboardMilestones().map((milestone) => `<option value="${escapeHtml(milestone)}">${escapeHtml(milestone)}</option>`).join("");
}


function renderDashboardScheduleItem(entry) {
  const canToggle = canEditProjectDetail();
  return `<article class="dashboard-schedule-item" data-dashboard-schedule-id="${escapeAttr(entry.id)}">
    <label class="dashboard-schedule-check" title="완료">
      <input class="dashboard-schedule-check-input" type="checkbox" data-dashboard-schedule-complete="${escapeAttr(entry.id)}" ${entry.completed ? "checked" : ""} ${canToggle ? "" : "disabled"} />
      <span class="dashboard-schedule-check-text">완료</span>
    </label>
    <div class="dashboard-schedule-body">
      <div class="dashboard-schedule-title-row">
        <strong class="dashboard-schedule-name">${escapeHtml(entry.projectName || "-")}</strong>
      </div>
      <p class="dashboard-schedule-meta">${escapeHtml(entry.date || "-")} · ${escapeHtml(entry.milestone || "-")} · ${escapeHtml(scheduleStaffBadgeText(entry))}</p>
      <p class="dashboard-schedule-detail">${escapeHtml(entry.detail || "-")}</p>
    </div>
  </article>`;
}

function toggleScheduleCompleted(entryId, completed) {
  const targetProject = projects.find((project) => (project.schedules || []).some((entry) => entry.id === entryId));
  const targetEntry = targetProject ? (targetProject.schedules || []).find((entry) => entry.id === entryId) : null;
  if (!canManageProjectScheduleEntry(targetProject, targetEntry)) return false;
  projects.forEach((project) => {
    (project.schedules || []).forEach((entry) => {
      if (entry.id === entryId) entry.completed = Boolean(completed);
    });
  });
  persistEntry();
  renderScheduleViews();
  renderDashboard();
  const project = selectedProject();
  if (project) renderProjectSchedules(project);
  return true;
}

function bindDashboardScheduleActions(container) {
  container.querySelectorAll(".dashboard-schedule-check").forEach((label) => {
    label.addEventListener("click", (event) => event.stopPropagation());
  });
  container.querySelectorAll("[data-dashboard-schedule-complete]").forEach((input) => {
    input.addEventListener("click", (event) => event.stopPropagation());
    input.addEventListener("change", (event) => {
      event.stopPropagation();
      const checked = input.checked;
      if (!toggleScheduleCompleted(input.dataset.dashboardScheduleComplete, checked)) {
        input.checked = !checked;
      }
    });
  });
  container.querySelectorAll("[data-dashboard-schedule-id]").forEach((item) => {
    item.addEventListener("click", () => openProjectDetailFromSchedule(item.dataset.dashboardScheduleId));
  });
}

function renderDashboardSchedules() {
  const today = todayDate();
  const weekStart = startOfWeekMonday(today);
  const weekEnd = addDays(weekStart, 6);
  const entries = scheduleEntriesWithDemo()
    .filter((entry) => !entry.completed)
    .sort((a, b) => String(a.date || "").localeCompare(String(b.date || "")));
  const todayEntries = entries.filter((entry) => entry.date === today);
  const weekEntries = entries.filter((entry) => String(entry.date || "") >= weekStart && String(entry.date || "") <= weekEnd);
  setText("dashboardTodayScheduleDate", today);
  setText("dashboardTodayScheduleCount", todayEntries.length.toLocaleString("ko-KR"));
  setText("dashboardWeekScheduleRange", `${weekStart} ~ ${weekEnd}`);
  setText("dashboardWeekScheduleCount", weekEntries.length.toLocaleString("ko-KR"));
  const todayBox = $("dashboardTodaySchedules");
  if (todayBox) {
    todayBox.innerHTML = todayEntries.length ? todayEntries.map(renderDashboardScheduleItem).join("") : '<p class="empty">오늘 확인할 일정이 없습니다.</p>';
    bindDashboardScheduleActions(todayBox);
  }
  const weekBox = $("dashboardWeekSchedules");
  if (weekBox) {
    weekBox.innerHTML = weekEntries.length ? weekEntries.map(renderDashboardScheduleItem).join("") : '<p class="empty">이번 주 확인할 일정이 없습니다.</p>';
    bindDashboardScheduleActions(weekBox);
  }
}


function renderDashboard() {
  const visible = accessibleProjects();
  const progressRows = progressProjects();
  const issueProjectCount = visible.filter((project) => project.hasIssue).length;
  $("activeCount").textContent = visible.length.toLocaleString("ko-KR");
  $("feedbackCount").textContent = progressRows.length.toLocaleString("ko-KR");
  $("monthlyCount").textContent = visible.filter((project) => project.monthlyCollection).length.toLocaleString("ko-KR");
  $("issueCount").textContent = issueProjectCount.toLocaleString("ko-KR");
  const metricsGrid = $("statusChart")?.closest(".dashboard-grid");
  const canViewMetrics = canViewDashboardProjectMetrics();
  if (metricsGrid) metricsGrid.style.display = canViewMetrics ? "" : "none";
  if (canViewMetrics) {
    renderStatusChart(progressRows);
    renderStatusSummary(progressRows);
  }
  renderDashboardSchedules();
}

function progressMilestoneColumns(rows) {
  const present = new Set(rows.map((project) => projectMilestone(project)).filter(Boolean));
  const ordered = dashboardVisibleMilestones().filter((milestone) => present.has(milestone));
  const extras = [...present]
    .filter((milestone) => !ordered.includes(milestone) && !isInactiveProgressMilestone(milestone))
    .sort((a, b) => a.localeCompare(b, "ko"));
  const columns = [...ordered, ...extras];
  if (rows.some((project) => !projectMilestone(project))) columns.push("미지정");
  return columns;
}

function milestoneMatchCount(rows, milestone) {
  return rows.filter((project) => {
    const value = projectMilestone(project);
    return milestone === "미지정" ? !value : value === milestone;
  }).length;
}

function renderStatusChart(rows) {
  const chart = $("statusChart");
  if (!chart) return;
  if (!rows.length) {
    chart.innerHTML = '<div class="admin-lock"><strong>진행 프로젝트가 없습니다.</strong></div>';
    return;
  }

  const milestones = dashboardVisibleMilestones();
  const colors = ["#ffd767", "#95c77f", "#7bb6f6", "#f59e9e", "#b7a4f6", "#70d6c7", "#f6a96b", "#a3a3a3", "#f472b6", "#38bdf8"];
  const pmNames = [...new Set(rows.map((project) => String(project.pm || "").trim()).filter(Boolean))].sort((a, b) =>
    a.localeCompare(b, "ko")
  );
  const staffGroups = pmNames.map((name, index) => ({ name, color: colors[index % colors.length] }));
  if (rows.some((project) => !String(project.pm || "").trim())) {
    staffGroups.push({ name: "미지정", color: colors[staffGroups.length % colors.length] });
  }

  if (!staffGroups.length) {
    chart.innerHTML = '<div class="admin-lock"><strong>표시할 PM이 없습니다.</strong></div>';
    return;
  }

  const chartData = milestones.map((milestone) => ({
    milestone,
    values: staffGroups.map((group) =>
      rows.filter((project) => {
        const pm = String(project.pm || "").trim() || "미지정";
        return projectMilestone(project) === milestone && pm === group.name;
      }).length
    ),
  }));

  const maxValue = Math.max(0, ...chartData.flatMap((item) => item.values));
  const yMax = Math.max(5, Math.ceil(maxValue / 5) * 5);
  const yTicks = [yMax, Math.round((yMax * 2) / 3), Math.round(yMax / 3), 0];
  const barWidth = staffGroups.length > 5 ? 8 : staffGroups.length > 3 ? 10 : 14;

  chart.innerHTML = `
    <div class="chart-legend">
      ${staffGroups.map((group) => `<span><i style="background:${group.color}"></i>${escapeHtml(group.name)}</span>`).join("")}
    </div>
    <div class="chart-area">
      <div class="y-axis">
        ${yTicks.map((tick) => `<span>${tick}</span>`).join("")}
      </div>
      <div class="bars" style="grid-template-columns: repeat(${milestones.length}, minmax(74px, 1fr));">
        ${chartData
          .map(
            (item) => `
              <div class="bar-group">
                <div class="bar-pair">
                  ${item.values
                    .map((value, index) => {
                      const height = value ? Math.max(10, Math.round((value / yMax) * 170)) : 2;
                      return `<div class="bar" style="height:${height}px;width:${barWidth}px;background:${staffGroups[index].color}" title="${escapeAttr(staffGroups[index].name)}: ${value}"><span class="bar-value">${value}</span></div>`;
                    })
                    .join("")}
                </div>
                <div class="bar-label">${escapeHtml(item.milestone)}</div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderStatusSummary(rows) {
  const summary = $("statusSummary");
  if (!summary) return;

  const milestoneOrder = [
    ...dashboardVisibleMilestones(),
    ...dashboardMilestones().filter((milestone) => !dashboardVisibleMilestones().includes(milestone)),
  ];
  const present = [...new Set(rows.map((project) => projectMilestone(project)).filter(Boolean))];
  const ordered = milestoneOrder.filter((milestone) => present.includes(milestone));
  const extras = present.filter((milestone) => !ordered.includes(milestone)).sort((a, b) => a.localeCompare(b, "ko"));
  const labels = [...ordered, ...extras];
  if (rows.some((project) => !projectMilestone(project))) labels.push("미지정");
  const counts = labels
    .map((milestone) => [milestone, milestoneMatchCount(rows, milestone)])
    .filter(([, count]) => count > 0);

  summary.innerHTML = counts.length
    ? counts
        .map(
          ([milestone, count]) =>
            `<button class="status-filter-btn" data-milestone-status="${escapeAttr(milestone)}" type="button"><span>${escapeHtml(milestone)}</span><strong>${count}</strong></button>`
        )
        .join("")
    : '<p class="empty">진행 프로젝트가 없습니다.</p>';

  summary.querySelectorAll("[data-milestone-status]").forEach((button) => {
    button.addEventListener("click", () => {
      applyDashboardMilestoneFilter(button.dataset.milestoneStatus);
    });
  });
}

const HOME_LINK_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`;
const INTRANET_LINK_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="2" width="16" height="20" rx="2"/><path d="M9 22v-4h6v4"/><path d="M9 6h.01"/><path d="M15 6h.01"/><path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M9 14h.01"/><path d="M15 14h.01"/></svg>`;
const DESIGN_LINK_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="4" rx="1"/><rect x="14" y="10" width="7" height="11" rx="1"/><rect x="3" y="13" width="7" height="8" rx="1"/></svg>`;

const URL_FIELD_LABELS = {
  shortcutUrl: { register: "홈페이지 URL 등록", aria: "홈페이지" },
  intranetUrl: { register: "인트라 URL 등록", aria: "인트라" },
  designUrl: { register: "화면설계 URL 등록", aria: "화면설계" },
};
const QUOTE_DOWNLOAD_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12"/><path d="m8 11 4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>`;
function hasDepositDate(project) {
  return Boolean(String(project?.depositDate || "").trim());
}


function isClosedProject(project) {
  const displayStatus = String(projectDisplayStatus(project) || "").trim();
  const milestone = String(projectMilestone(project) || "").trim();
  return CLOSED_WORK_STATUSES.includes(displayStatus) || CLOSED_MILESTONES.includes(milestone);
}

function dueDateStatus(project) {
  if (!project?.dueDate || isClosedProject(project)) return null;
  const due = parseDateParts(project.dueDate);
  if (!due) return null;
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const dueDate = new Date(due.year, due.month - 1, due.day);
  const daysLeft = Math.ceil((dueDate - today) / 86400000);
  if (daysLeft < 0) return { label: "지연", className: "status-badge rejected" };
  if (daysLeft <= 14) return { label: "주의", className: "badge warn" };
  return null;
}

function buildDueDateBadge(project) {
  const status = dueDateStatus(project);
  if (!status) return "";
  return `<span class="${status.className}" title="납기일 ${escapeAttr(formatDate(project.dueDate))}">${escapeHtml(status.label)}</span>`;
}

function projectNoSortValue(project) {
  const value = String(project?.projectNo || "").trim();
  const numeric = Number(value);
  return { value, numeric, hasNumeric: value !== "" && Number.isFinite(numeric) };
}

function compareProjectNo(a, b) {
  const left = projectNoSortValue(a);
  const right = projectNoSortValue(b);
  if (left.hasNumeric && right.hasNumeric && left.numeric !== right.numeric) return left.numeric - right.numeric;
  return left.value.localeCompare(right.value, "ko", { numeric: true, sensitivity: "base" });
}

function compareProjectMilestone(a, b) {
  return String(projectMilestone(a) || "").localeCompare(String(projectMilestone(b) || ""), "ko", { numeric: true, sensitivity: "base" });
}

function sortedProjectRows(rows, listName) {
  const state = listSortState[listName] || {};
  if (!state.key || !state.direction) return rows;
  const direction = state.direction === "desc" ? -1 : 1;
  const compare = state.key === "milestone" ? compareProjectMilestone : compareProjectNo;
  return [...rows].sort((a, b) => compare(a, b) * direction);
}

function updateListSortUi() {
  document.querySelectorAll("[data-sort-list][data-sort-key]").forEach((trigger) => {
    const state = listSortState[trigger.dataset.sortList] || {};
    const active = state.key === trigger.dataset.sortKey && Boolean(state.direction);
    const icon = trigger.querySelector("[data-sort-icon]");
    if (icon) icon.textContent = active ? (state.direction === "asc" ? "↑" : "↓") : "↕";
    trigger.classList.toggle("is-active", active);
  });
}

function toggleListSort(listName, key) {
  const state = listSortState[listName];
  if (!state) return;
  state.direction = state.key === key && state.direction === "asc" ? "desc" : "asc";
  state.key = key;
  if (listName === "monthly") renderMonthlyRows();
  else if (listName === "issues") renderIssueProjectRows();
  else renderRows();
}

function buildProjectFlagIcons(project) {
  const flags = [];
  if (project.hasForeignLanguage) {
    flags.push(`<span class="flag-text-btn flag-lang" title="다국어">다국어</span>`);
  }
  if (project.monthlyCollection) {
    flags.push(`<span class="flag-text-btn flag-money" title="당월수금">당월수금</span>`);
  }
  if (project.hasIssue) {
    flags.push(`<span class="flag-text-btn flag-issue" title="이슈">이슈</span>`);
  }
  if (project.hostingType === "단독서버") {
    flags.push(`<span class="flag-text-btn flag-server" title="단독서버">단독서버</span>`);
  }
  if (!flags.length) return "";
  return `<span class="project-flag-icons">${flags.join("")}</span>`;
}

function buildHomeShortcutButton(project) {
  const hasHome = Boolean(String(project.shortcutUrl || "").trim());
  return `<button class="shortcut-btn ${hasHome ? "" : "is-empty"}" data-link-project-id="${project.id}" data-link-field="shortcutUrl" type="button" title="${escapeAttr(hasHome ? project.shortcutUrl : "홈페이지 URL 등록")}" aria-label="홈페이지">${HOME_LINK_ICON}</button>`;
}

function buildIntranetShortcutButton(project) {
  const hasIntranet = Boolean(String(project.intranetUrl || "").trim());
  return `<button class="shortcut-btn intranet-link ${hasIntranet ? "" : "is-empty"}" data-link-project-id="${project.id}" data-link-field="intranetUrl" type="button" title="${escapeAttr(hasIntranet ? project.intranetUrl : "인트라 URL 등록")}" aria-label="인트라">${INTRANET_LINK_ICON}</button>`;
}

function buildDesignShortcutButton(project) {
  const hasDesign = Boolean(String(project.designUrl || "").trim());
  return `<button class="shortcut-btn design-link ${hasDesign ? "" : "is-empty"}" data-link-project-id="${project.id}" data-link-field="designUrl" type="button" title="${escapeAttr(hasDesign ? project.designUrl : "화면설계 URL 등록")}" aria-label="화면설계">${DESIGN_LINK_ICON}</button>`;
}

function buildShortcutActions(project) {
  return `<div class="shortcut-actions">${buildHomeShortcutButton(project)}${buildIntranetShortcutButton(project)}${buildDesignShortcutButton(project)}</div>`;
}

function buildHomeAndIntranetShortcutActions(project) {
  return `<div class="shortcut-actions">${buildHomeShortcutButton(project)}${buildIntranetShortcutButton(project)}</div>`;
}

function attachShortcutButtonHandlers(container) {
  if (!container) return;
  container.querySelectorAll("[data-link-project-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const project = findProjectById(button.dataset.linkProjectId);
      openProjectLink(project, button.dataset.linkField || "shortcutUrl");
    });
  });
}

function buildQuoteCell(project) {
  if (project.quoteFileData) {
    const title = project.quoteFileName ? `${project.quoteFileName} 보기` : "견적서 보기";
    return `<button class="quote-download-btn" data-quote-view-id="${project.id}" type="button" title="${escapeAttr(title)}" aria-label="견적서 보기">${QUOTE_DOWNLOAD_ICON}</button>`;
  }
  if (!canManageProjectQuote()) return '<span class="muted">미등록</span>';
  return `<button class="quote-unregistered" data-quote-upload-project-id="${project.id}" type="button" title="견적서 등록" aria-label="견적서 등록">미등록</button>`;
}

function findProjectById(id) {
  if (isCreatingProject && draftProject?.id === id) return draftProject;
  return projects.find((item) => item.id === id) || detailAccessibleProjects().find((item) => item.id === id);
}

function normalizeShortcutUrl(url) {
  const value = String(url || "").trim();
  if (!value) return "";
  if (/^https?:\/\//i.test(value)) return value;
  return `https://${value}`;
}

function openShortcutUrl(url) {
  const normalized = normalizeShortcutUrl(url);
  if (!normalized) return false;
  window.open(normalized, "_blank", "noopener,noreferrer");
  return true;
}

function openShortcutDialog(projectId, field = "shortcutUrl") {
  const project = findProjectById(projectId);
  if (!project) return;
  editingShortcutProjectId = projectId;
  editingShortcutField = field;
  const titles = {
    shortcutUrl: "홈페이지 URL 등록",
    intranetUrl: "인트라 URL 등록",
    designUrl: "화면설계 URL 등록",
  };
  setText("shortcutDialogTitle", titles[field] || "URL 등록");
  setText("shortcutProjectName", `${project.projectNo || "-"} · ${project.name || "이름 없음"}`);
  setValue("shortcutUrlInput", project[field] || "");
  $("shortcutDialog")?.showModal();
  $("shortcutUrlInput")?.focus();
}

function submitShortcutUrl(event) {
  if (!requireWritableAction()) {
    event.preventDefault();
    return;
  }
  event.preventDefault();
  const project = findProjectById(editingShortcutProjectId);
  const field = URL_FIELD_LABELS[editingShortcutField] ? editingShortcutField : "shortcutUrl";
  if (!project) return;
  const url = normalizeShortcutUrl(valueOf("shortcutUrlInput"));
  if (!url) return;
  project[field] = url;
  if (!isCreatingProject) void persist();
  $("shortcutDialog")?.close();
  editingShortcutProjectId = "";
  editingShortcutField = "shortcutUrl";
  renderRows();
  renderMonthlyRows();
  renderIssueProjectRows();
  renderDetail();
  openShortcutUrl(url);
}

function openProjectLink(project, field = "shortcutUrl") {
  if (!project) return;
  if (openShortcutUrl(project[field])) return;
  openShortcutDialog(project.id, field);
}

function dataUrlToBlob(dataUrl) {
  const parts = String(dataUrl).split(",");
  const header = parts[0] || "";
  const data = parts[1] || "";
  const mime = header.match(/data:(.*?);/)?.[1] || "application/pdf";
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type: mime });
}

function viewQuoteForProject(project) {
  if (!project?.quoteFileData) return;
  const source = project.quoteFileData;
  let objectUrl = "";
  try {
    const url = String(source).startsWith("data:")
      ? (objectUrl = URL.createObjectURL(dataUrlToBlob(source)))
      : source;
    const title = escapeHtml(project.quoteFileName || `${project.projectNo || "quote"}.pdf`);
    const viewer = window.open("", "_blank");
    if (!viewer) {
      alert("팝업이 차단되어 견적서를 열 수 없습니다. 팝업 허용 후 다시 시도해 주세요.");
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      return;
    }
    viewer.document.write(`<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8" />
    <title>${title}</title>
    <style>
      html, body { margin: 0; width: 100%; height: 100%; background: #111; }
      embed, iframe { border: 0; width: 100%; height: 100%; }
    </style>
  </head>
  <body>
    <embed src="${url}" type="application/pdf" />
  </body>
</html>`);
    viewer.document.close();
    viewer.focus();
  } catch (error) {
    console.error(error);
    alert("견적서 PDF를 열 수 없습니다. 파일을 다시 등록해 주세요.");
  }
}

function renderRows() {
  const rows = sortedProjectRows(filteredProjects(), "projects");
  updateListSortUi();
  setText("projectsTitle", `프로젝트 관리(${rows.length.toLocaleString("ko-KR")}건)`);
  const tbody = $("projectRows");
  if (!tbody) return;
  tbody.innerHTML = rows
    .map((project) => {
      const displayStatus = project.status || project.progressStatus || "미지정";
      const milestone = project.milestone || "-";
      const contactPreview = renderMatchedClientContacts(project);
      return `
        <tr data-id="${project.id}" class="${[
          project.id === selectedId && document.body.classList.contains("detail-open") ? "selected" : "",
          contactPreview ? "has-contact-preview" : "",
        ]
          .filter(Boolean)
          .join(" ")}">
          <td>${escapeHtml(project.projectNo)}</td>
          <td class="project-name-cell">
            <div class="project-name-stack">
              <div class="project-title-cell">
                ${buildDueDateBadge(project)}
                <span class="project-name">${escapeHtml(project.name || "이름 없음")}</span>
                ${buildProjectFlagIcons(project)}
              </div>
              ${contactPreview}
            </div>
          </td>
          <td>${escapeHtml(milestone)}</td>
          <td>${
            canEditProjectDetail()
              ? `<button class="badge status-edit ${workStatusBadgeClass(displayStatus)}" data-status-project-id="${project.id}" type="button">${escapeHtml(displayStatus)}</button>`
              : `<span class="badge ${workStatusBadgeClass(displayStatus)}">${escapeHtml(displayStatus)}</span>`
          }</td>
          <td>${projectStaffCell(project, "pm", "pm")}</td>
          <td>${projectStaffCell(project, "designer", "designer")}</td>
          <td>${projectStaffCell(project, "publisher", "publisher")}</td>
          <td>${projectStaffCell(project, "programmer", "programmer")}</td>
          <td>${buildShortcutActions(project)}</td>
          <td>${buildQuoteCell(project)}</td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", (event) => {
      event.stopPropagation();
      closeListFilterMenus();
      cancelCreateProject();
      selectedId = row.dataset.id;
      document.body.classList.remove("schedule-detail-open");
      document.body.classList.add("detail-open");
      closeDetailDropdowns();
      renderAll(false);
      saveUiSessionState();
    });
  });

  tbody.querySelectorAll("[data-status-project-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      openStatusDialog(button.dataset.statusProjectId);
    });
  });

  tbody.querySelectorAll("[data-quote-view-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const project = findProjectById(button.dataset.quoteViewId);
      viewQuoteForProject(project);
    });
  });

  tbody.querySelectorAll("[data-quote-upload-project-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      quoteUploadProjectId = button.dataset.quoteUploadProjectId;
      $("quoteFile")?.click();
    });
  });

  attachShortcutButtonHandlers(tbody);
}

function viewDateParts(viewDate = new Date()) {
  return {
    year: viewDate.getFullYear(),
    month: viewDate.getMonth() + 1,
    day: viewDate.getDate(),
  };
}

function parseDateParts(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  const match = text.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (!match) return null;
  return {
    year: Number(match[1]),
    month: Number(match[2]),
    day: Number(match[3]),
  };
}

function isCurrentMonthDate(value, viewDate = new Date()) {
  const date = parseDateParts(value);
  if (!date) return false;
  const view = viewDateParts(viewDate);
  return date.year === view.year && date.month === view.month;
}

function isMonthlyCollectionVisible(project, viewDate = new Date()) {
  if (!project?.monthlyCollection) return false;
  const depositDate = String(project.depositDate || "").trim();
  if (!depositDate) return true;
  return isCurrentMonthDate(depositDate, viewDate);
}

function monthlyIssueProjectSource() {
  return canViewMonthlyAndIssues() ? projects : [];
}

function monthlyProjects() {
  return monthlyIssueProjectSource().filter((project) => {
    // 당월수금 목록은 오픈일자가 아니라 입금일(수금 완료일) 기준으로만 노출한다.
    return isMonthlyCollectionVisible(project);
  });
}

function isCollectionCompleted(project) {
  return Boolean(String(project.depositDate || "").trim());
}

function moneyAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? amount : 0;
}

function renderMonthlySummary(rows = monthlyProjects()) {
  const completed = rows.filter(isCollectionCompleted);
  const totalAmount = rows.reduce((sum, project) => sum + moneyAmount(project.balance), 0);
  const collectedAmount = completed.reduce((sum, project) => sum + moneyAmount(project.balance), 0);

  if ($("monthlyProjectCount")) $("monthlyProjectCount").textContent = rows.length.toLocaleString("ko-KR");
  if ($("monthlyCompletedCount")) $("monthlyCompletedCount").textContent = completed.length.toLocaleString("ko-KR");
  if ($("monthlyTotalAmount")) $("monthlyTotalAmount").textContent = formatMoney(totalAmount);
  if ($("monthlyCollectedAmount")) $("monthlyCollectedAmount").textContent = formatMoney(collectedAmount);
}

function renderMonthlyRows() {
  const rows = sortedProjectRows(monthlyProjects(), "monthly");
  updateListSortUi();
  const tbody = $("monthlyRows");
  if (!tbody) return;

  renderMonthlySummary(rows);

  tbody.innerHTML = rows.length
    ? rows
        .map((project) => {
          const milestone = project.milestone || "-";
          const progressStatus = project.status || project.progressStatus || "미지정";
          const depositDate = project.depositDate || "";
          const completed = isCollectionCompleted(project);
          return `
            <tr data-monthly-id="${project.id}" class="${project.id === selectedId && document.body.classList.contains("detail-open") ? "selected" : ""}">
              <td>${escapeHtml(project.projectNo)}</td>
              <td>
                <div class="project-title-cell">
                  ${buildDueDateBadge(project)}
                  <span class="project-name">${escapeHtml(project.name || "이름 없음")}</span>
                  ${buildProjectFlagIcons(project)}
                </div>
              </td>
              <td>${escapeHtml(milestone)}</td>
              <td><span class="badge ${workStatusBadgeClass(progressStatus)}">${escapeHtml(progressStatus)}</span></td>
              <td>${formatMoney(project.balance)}</td>
              <td>${formatDate(depositDate)}</td>
              <td>${completed ? '<button class="collection-done-btn" type="button">수금완료</button>' : ""}</td>
              <td>${buildHomeAndIntranetShortcutActions(project)}</td>
            </tr>
          `;
        })
        .join("")
    : '<tr><td colspan="8" class="empty-cell">당월 수금체크된 프로젝트가 없습니다.</td></tr>';

  tbody.querySelectorAll("[data-monthly-id]").forEach((row) => {
    row.addEventListener("click", (event) => {
      event.stopPropagation();
      closeListFilterMenus();
      cancelCreateProject();
      selectedId = row.dataset.monthlyId;
      document.body.classList.remove("schedule-detail-open");
      document.body.classList.add("detail-open");
      closeDetailDropdowns();
      renderDetail();
      saveUiSessionState();
      tbody.querySelectorAll("tr[data-monthly-id]").forEach((item) => {
        item.classList.toggle("selected", item.dataset.monthlyId === selectedId);
      });
    });
  });

  attachShortcutButtonHandlers(tbody);
}

function closeDetailDropdowns() {
  document.querySelectorAll(".detail-dropdown").forEach((dropdown) => {
    dropdown.removeAttribute("open");
  });
}

function updateDetailBadges(project) {
  const badges = $("detailBadges");
  if (!badges) return;
  const tags = [];
  if (project.hasForeignLanguage || checkedOf("hasForeignLanguage")) tags.push('<span class="badge warn">외국어</span>');
  const landingChecked = document.querySelector('[name="hasLanding"]:checked')?.value === "landing" || project.hasLanding;
  if (landingChecked) tags.push('<span class="badge warn">랜딩</span>');
  const hosting = document.querySelector('[name="hostingType"]:checked')?.value || project.hostingType;
  if (hosting === "단독서버") tags.push('<span class="badge warn">단독서버</span>');
  badges.innerHTML = tags.join("");
}

function updateDetailFilledState() {
  const grid = document.querySelector(".detail-main-grid");
  if (!grid) return;

  grid.querySelectorAll("input:not([type='checkbox']):not([type='radio']), select, textarea").forEach((field) => {
    field.classList.toggle("is-filled", String(field.value || "").trim() !== "");
  });

  grid.querySelectorAll("label.check-option").forEach((label) => {
    const checkbox = label.querySelector('input[type="checkbox"]');
    if (!checkbox) return;
    label.classList.toggle("is-filled", Boolean(checkbox.checked));
  });

  grid.querySelectorAll("div.choice-row").forEach((row) => {
    const checked = row.querySelector('input[type="radio"]:checked, input[type="checkbox"]:checked');
    row.classList.toggle("is-filled", Boolean(checked));
  });
}

function updateDetailHeaderChecks() {
  $("issueCheckLabel")?.classList.toggle("is-active", checkedOf("hasIssue"));
  $("monthlyCollectionLabel")?.classList.toggle("is-active", checkedOf("monthlyCollection"));
}

function projectCompletionStageType(stage) {
  const key = String(stage?.key || "");
  if (key.startsWith("design_")) return "design";
  if (key.startsWith("publishing_")) return "publishing";
  if (key.startsWith("program_")) return "program";
  return "";
}

function projectCompletionTypeLabel(type) {
  const labels = {
    design: "디자인완료",
    publishing: "퍼블리싱완료",
    program: "프로그램완료",
  };
  return labels[String(type || "")] || "";
}

function projectCompletionTypeShortLabel(type) {
  const labels = {
    design: "디자인",
    publishing: "퍼블리싱",
    program: "프로그램",
  };
  return labels[String(type || "")] || "";
}

function projectCompletionProgressLabel(project, stage) {
  const flow = normalizeProjectCompletionFlow(project?.completionFlow);
  return projectCompletionTypeLabel(flow.pendingType) || projectCompletionTypeLabel(projectCompletionStageType(stage)) || stage?.label || "완료";
}

function canOpenProjectCompletionDialog(project = selectedProject()) {
  const stage = projectCompletionStage(project);
  if (!currentUser || isReadOnlyMode() || isCreatingProject || stage?.actor !== "worker") return false;
  if (isAdmin()) return true;
  return (isDepartment("디자인", "디자이너") || isDepartment("퍼블리싱", "퍼블리셔") || isDepartment("프로그램", "프로그래머")) && userCanActProjectCompletion(project, stage);
}

function canCompleteProjectFromDetail(project = selectedProject()) {
  const stage = projectCompletionStage(project);
  if (!currentUser || isReadOnlyMode() || isCreatingProject || !stage) return false;
  if (stage.actor === "worker") return canOpenProjectCompletionDialog(project);
  return userCanActProjectCompletion(project, stage);
}

function openProjectCompletionDialog() {
  const project = selectedProject();
  const stage = projectCompletionStage(project);
  if (!project || !canOpenProjectCompletionDialog(project)) return;
  setText("projectCompletionDialogProjectName", project.name || project.projectNo || "");
  setText("projectCompletionDialogMessage", "");
  setValue("projectCompletionType", projectCompletionStageType(stage) || "design");
  setValue("projectCompletionMemo", "");
  $("projectCompletionDialog")?.showModal();
}

function closeProjectCompletionDialog() {
  setText("projectCompletionDialogMessage", "");
  setValue("projectCompletionMemo", "");
  $("projectCompletionDialog")?.close();
}

async function submitProjectCompletionDialog(event) {
  event.preventDefault();
  const project = selectedProject();
  const stage = projectCompletionStage(project);
  const selectedType = valueOf("projectCompletionType");
  const memo = valueOf("projectCompletionMemo").trim();
  if (!project || !stage || !canOpenProjectCompletionDialog(project)) return;
  if (selectedType !== projectCompletionStageType(stage)) {
    setText("projectCompletionDialogMessage", "현재 완료 단계와 선택한 완료 구분이 맞지 않습니다.");
    return;
  }
  await advanceProjectCompletion(project.id, "approve", "", selectedType, memo);
  closeProjectCompletionDialog();
}

function applyReadOnlyUi() {
  const readOnly = isReadOnlyMode();
  const canEdit = !readOnly && canEditProjectDetail();
  const canEditActivity = !readOnly && canEditProjectActivity();
  const canEditIssues = !readOnly && canEditProjectIssues();
  const canEditCommunications = !readOnly && canEditProjectCommunications();
  const canDeleteActivityEntries = !readOnly && canDeleteProjectActivityEntries();
  const canQuote = !readOnly && canManageProjectQuote();
  const canCreate = !readOnly && canCreateProject();
  const canWriteProject = isCreatingProject ? canCreate : canEdit;
  const project = selectedProject();
  const canCreateSchedule = canCreateProjectSchedule(project);
  const completionStage = projectCompletionStage(project);
  const canCompleteProject = canCompleteProjectFromDetail(project);
  const visibilityById = {
    newProject: canCreate,
    saveDetailBtn: canWriteProject,
    deleteProject: isAdmin(),
    addIssue: canEditIssues,
    addClientContact: canEditActivity,
    addCommunication: canEditCommunications,
    projectCompleteAction: canCompleteProject,
    addScheduleFromCalendar: Boolean(currentUser && (canManageAllProjectSchedules() || canUseAssignedProjectSchedules())),
    addScheduleFromList: Boolean(currentUser && (canManageAllProjectSchedules() || canUseAssignedProjectSchedules())),
  };
  Object.entries(visibilityById).forEach(([id, visible]) => {
    const element = $(id);
    if (element) element.classList.toggle("hidden", !visible);
  });
  if ($("projectCompleteAction")) $("projectCompleteAction").textContent = completionStage ? "완료" : "완료";

  const quoteAction = $("quoteAction");
  if (quoteAction && !selectedProject()?.quoteFileData) quoteAction.classList.toggle("hidden", !canQuote);
  [
    { id: "shortcutAction", field: "shortcutUrl" },
    { id: "intranetAction", field: "intranetUrl" },
    { id: "designAction", field: "designUrl" },
  ].forEach(({ id, field }) => {
    const element = $(id);
    if (element && !String(selectedProject()?.[field] || "").trim()) {
      element.classList.toggle("hidden", !canEdit);
    }
  });

  const detailForm = $("detailForm");
  if (!detailForm) return;
  detailForm.querySelectorAll("input, select, textarea").forEach((field) => {
    if (field.id === "detailSearchInput") return;
    if (field.id === "quoteFile") {
      field.disabled = !canQuote;
      return;
    }
    field.disabled = !canWriteProject;
  });
  const projectNoField = $("projectNo");
  if (projectNoField) {
    projectNoField.readOnly = true;
    projectNoField.disabled = false;
    projectNoField.classList.toggle("is-readonly", true);
  }
  detailForm.querySelectorAll(".project-schedule-complete-input").forEach((input) => {
    const project = selectedProject();
    const entry = project ? (project.schedules || []).find((item) => item.id === input.dataset.scheduleEntryId) : null;
    input.disabled = !canManageProjectScheduleEntry(project, entry);
  });
  projectStaffFields.forEach((id) => {
    const field = $(id);
    if (!field) return;
    field.readOnly = true;
    field.classList.toggle("is-readonly", true);
  });
  detailForm.querySelectorAll(".issue-edit, .issue-save, .issue-cancel").forEach((button) => {
    button.classList.toggle("hidden", !canEditIssues);
  });
  detailForm.querySelectorAll(".issue-delete").forEach((button) => {
    button.classList.toggle("hidden", !canDeleteActivityEntries);
  });
  detailForm.querySelectorAll(".issue-complete-input, .issue-edit, .issue-delete, .issue-save, .issue-cancel").forEach((element) => {
    if (element.matches("input")) element.disabled = !canEditIssues;
  });
  detailForm.querySelectorAll(".contact-edit, .contact-delete, .contact-save, .contact-cancel").forEach((button) => {
    button.classList.toggle("hidden", !canEditActivity);
  });
  detailForm.querySelectorAll(".communication-edit, .communication-save, .communication-cancel").forEach((button) => {
    button.classList.toggle("hidden", !canEditCommunications);
  });
  detailForm.querySelectorAll(".communication-delete").forEach((button) => {
    button.classList.toggle("hidden", !canDeleteActivityEntries);
  });
  detailForm.querySelectorAll("#clientContactList input, #clientContactList select, #clientContactList textarea").forEach((field) => {
    field.disabled = !canEditActivity;
  });
  detailForm.querySelectorAll("#issueList input, #issueList select, #issueList textarea, #communicationList input, #communicationList select, #communicationList textarea").forEach((field) => {
    field.disabled = field.closest("#issueList") ? !canEditIssues : !canEditCommunications;
  });
  detailForm.querySelectorAll("#addProjectSchedule").forEach((element) => {
    element.classList.toggle("hidden", !canCreateSchedule);
  });
}

function renderDetail() {
  const project = selectedProject();
  if (!project) return;
  if (!isCreatingProject) selectedId = project.id;
  setText("detailHeading", project.name || (isCreatingProject ? "신규 프로젝트" : "프로젝트 상세"));
  setText(
    "saveState",
    isCreatingProject
      ? "내용을 입력한 뒤 저장하면 프로젝트가 생성됩니다."
      : `#${project.projectNo || "-"} · 견적가 ${formatMoney(project.contractAmount)}`
  );
  $("detailSearchWrap")?.classList.toggle("hidden", isCreatingProject);
  if (isCreatingProject && $("detailBadges")) $("detailBadges").innerHTML = "";

  editableFields.forEach((field) => {
    setValue(field, project[field] ?? "");
  });
  if (currentUser && isDepartment("pm")) {
    setValue("pm", currentPmName());
  }

  document.querySelectorAll('[name="hostingType"]').forEach((radio) => {
    radio.checked = radio.value === (project.hostingType || "일반 웹호스팅");
  });
  setChecked("hasForeignLanguage", project.hasForeignLanguage);
  setChecked("monthlyCollection", project.monthlyCollection);
  setChecked("hasIssue", project.hasIssue);
  document.querySelectorAll('[name="hasLanding"]').forEach((radio) => {
    radio.checked = radio.value === (project.hasLanding ? "landing" : "normal");
  });
  $("issueCheckLabel")?.classList.toggle("is-active", Boolean(project.hasIssue));
  $("monthlyCollectionLabel")?.classList.toggle("is-active", Boolean(project.monthlyCollection));

  const hasQuote = Boolean(project.quoteFileData);
  const hasHome = Boolean(String(project.shortcutUrl || "").trim());
  const hasIntranet = Boolean(String(project.intranetUrl || "").trim());
  const hasDesign = Boolean(String(project.designUrl || "").trim());
  $("quoteAction")?.classList.toggle("is-active", hasQuote);
  if ($("quoteAction")) {
    $("quoteAction").title = hasQuote ? `${project.quoteFileName || "견적서"} 보기` : "견적서 등록";
    $("quoteAction").setAttribute("aria-label", hasQuote ? "견적서 보기" : "견적서 등록");
  }
  $("shortcutAction")?.classList.toggle("is-active", hasHome);
  if ($("shortcutAction")) {
    $("shortcutAction").title = hasHome ? project.shortcutUrl : "홈페이지 URL 등록";
    $("shortcutAction").setAttribute("aria-label", hasHome ? "홈페이지" : "홈페이지 URL 등록");
  }
  $("intranetAction")?.classList.toggle("is-active", hasIntranet);
  if ($("intranetAction")) {
    $("intranetAction").title = hasIntranet ? project.intranetUrl : "인트라 URL 등록";
    $("intranetAction").setAttribute("aria-label", hasIntranet ? "인트라" : "인트라 URL 등록");
  }
  $("designAction")?.classList.toggle("is-active", hasDesign);
  if ($("designAction")) {
    $("designAction").title = hasDesign ? project.designUrl : "화면설계 URL 등록";
    $("designAction").setAttribute("aria-label", hasDesign ? "화면설계" : "화면설계 URL 등록");
  }
  $("deleteProject")?.classList.toggle("hidden", !isAdmin() || isCreatingProject);

  if (editingIssueId && !(project.issues || []).some((issue) => issue.id === editingIssueId)) editingIssueId = "";
  if (editingContactId && !(project.clientContacts || []).some((contact) => contact.id === editingContactId)) editingContactId = "";
  if (editingCommunicationId && !(project.communications || []).some((entry) => entry.id === editingCommunicationId)) editingCommunicationId = "";
  const workStackEntries = normalizeProjectCompletionFlow(project.completionFlow).history;
  if (editingProjectWorkStackId && !workStackEntries.some((entry) => entry.id === editingProjectWorkStackId)) editingProjectWorkStackId = "";

  if (!isCreatingProject) updateDetailBadges(project);
  updateDetailFilledState();
  renderIssues(project);
  renderClientContacts(project);
  renderCommunications(project);
  renderProjectWorkStack(project);
  renderProjectSchedules(project);
  applyReadOnlyUi();
}

function persistEntry() {
  if (!canEditProjectActivity() && !canEditProjectIssues() && !canEditProjectCommunications() && !isCreatingProject) return Promise.resolve();
  if (!isCreatingProject) return persist();
  return Promise.resolve();
}

function isBlankContact(contact) {
  return ![contact.name, contact.companyPhone, contact.personalPhone, contact.email].some((value) => String(value || "").trim());
}

function getDetailSearchQuery() {
  return valueOf("detailSearchInput").trim().toLowerCase();
}

function matchesDetailSearch(...values) {
  const query = getDetailSearchQuery();
  if (!query) return true;
  return values.some((value) => String(value || "").toLowerCase().includes(query));
}

function toggleIssueResolved(project, issueId, resolved) {
  if (!requireWritableAction()) return false;
  if (!canEditProjectIssues()) return false;
  const issue = (project.issues || []).find((item) => item.id === issueId);
  if (!issue) return false;
  issue.resolved = Boolean(resolved);
  if (resolved) issue.status = "프로젝트 참고";
  else if (issue.status === "프로젝트 참고" || issue.status === "해결완료") issue.status = "확인 필요";
  void persist();
  renderIssues(project);
  renderIssueProjectRows();
  return true;
}

function renderIssues(project) {
  const list = $("issueList");
  if (!list) return;
  project.issues = (project.issues || []).map(normalizeIssue);
  const allIssues = project.issues;
  const issues = allIssues.filter(
    (issue) =>
      issue.id === editingIssueId ||
      matchesDetailSearch(issue.memo, issue.status, issue.type, issue.title)
  );
  if (!allIssues.length) {
    list.innerHTML = '<p class="empty">등록된 이슈가 없습니다.</p>';
    return;
  }
  if (!issues.length) {
    list.innerHTML = '<p class="empty">검색 결과가 없습니다.</p>';
    return;
  }

  list.innerHTML = issues
    .map((issue) => {
      const isEditing = issue.id === editingIssueId;
      const resolved = isIssueResolved(issue);
      return `
        <article class="issue-card${resolved ? " is-issue-resolved" : ""}" data-issue-id="${issue.id}">
          <div class="issue-view ${isEditing ? "hidden" : ""}">
            <div class="entry-card-head issue-view-head">
              <div class="issue-head-main entry-card-head-main issue-meta-row">
                <label class="issue-complete-check check-option" title="프로젝트 참고">
                  <input type="checkbox" class="issue-complete-input" data-issue-id="${escapeAttr(issue.id)}" ${resolved ? "checked" : ""} />
                </label>
                <span class="issue-author">${escapeHtml(entryAuthorName(issue))}</span>
                <span class="issue-date">${escapeHtml(formatDate(issue.date))}</span>
                ${issue.status ? `<span class="issue-status-badge">${escapeHtml(issue.status)}</span>` : ""}
                ${issue.type ? `<span class="issue-type-badge">${escapeHtml(issue.type)}</span>` : ""}
              </div>
              <div class="entry-card-head-actions">
                <button class="ghost-btn issue-edit" type="button">수정</button>
                <button class="ghost-btn danger issue-delete" type="button">삭제</button>
              </div>
            </div>
            <p class="issue-text">${escapeHtml(issue.memo || "내용 없음")}</p>
          </div>
          <div class="issue-edit-panel ${isEditing ? "" : "hidden"}">
            <div class="issue-edit-fields">
              <label>이슈상태
                <select class="issue-status-input" required>${buildIssueFieldOptions(issueStatusOptions(), issue.status)}</select>
              </label>
              <label>이슈유형
                <select class="issue-type-input">${buildIssueFieldOptions(issueTypeOptions(), issue.type)}</select>
              </label>
            </div>
            <textarea class="issue-memo" placeholder="상세 내용을 입력하세요.">${escapeHtml(issue.memo)}</textarea>
            <div class="issue-actions">
              <button class="primary-btn issue-save" type="button">저장</button>
              <button class="ghost-btn issue-cancel" type="button">취소</button>
            </div>
          </div>
        </article>
      `;
    })
    .join("");

  list.querySelectorAll(".issue-card").forEach((card) => {
    const issue = allIssues.find((item) => item.id === card.dataset.issueId);
    if (!issue) return;
    const view = card.querySelector(".issue-view");
    const editPanel = card.querySelector(".issue-edit-panel");
    const textarea = card.querySelector(".issue-memo");
    const statusInput = card.querySelector(".issue-status-input");
    const typeInput = card.querySelector(".issue-type-input");
    const isEditing = issue.id === editingIssueId;

    card.querySelector(".issue-complete-input")?.addEventListener("change", (event) => {
      event.stopPropagation();
      const input = event.target;
      const checked = input.checked;
      if (!toggleIssueResolved(project, input.dataset.issueId, checked)) {
        input.checked = !checked;
      }
    });

    card.querySelector(".issue-edit").addEventListener("click", () => {
      if (!canEditProjectIssues()) return;
      editingIssueId = issue.id;
      const latestIssue = (selectedProject()?.issues || project.issues || []).map(normalizeIssue).find((item) => item.id === issue.id) || issue;
      statusInput.value = normalizeIssueStatus(latestIssue.status, "");
      typeInput.value = normalizeIssueType(latestIssue.type, "");
      textarea.value = latestIssue.memo || "";
      view.classList.add("hidden");
      editPanel.classList.remove("hidden");
      textarea.focus();
    });
    card.querySelector(".issue-cancel").addEventListener("click", () => {
      if (!canEditProjectIssues()) return;
      if (!issue.memo) {
        project.issues = project.issues.filter((item) => item.id !== issue.id);
        editingIssueId = "";
        persistEntry();
        renderIssues(project);
        renderIssueProjectRows();
        return;
      }
      if (editingIssueId === issue.id) editingIssueId = "";
      editPanel.classList.add("hidden");
      view.classList.remove("hidden");
      statusInput.value = normalizeIssueStatus(issue.status, "");
      typeInput.value = normalizeIssueType(issue.type, "");
      textarea.value = issue.memo || "";
    });
    card.querySelector(".issue-save").addEventListener("click", async () => {
      if (!canEditProjectIssues()) return;
      if (!statusInput.value) {
        alert("이슈상태를 선택해 주세요.");
        statusInput.focus();
        return;
      }
      issue.status = normalizeIssueStatus(statusInput.value);
      issue.type = normalizeIssueType(typeInput.value);
      issue.memo = textarea.value.trim();
      if (!issue.date) issue.date = todayDate();
      if (!issue.createdAt) issue.createdAt = new Date().toISOString();
      issue.resolved = issue.status === "프로젝트 참고";
      editingIssueId = "";
      await persistEntry();
      renderIssues(selectedProject() || project);
      renderIssueProjectRows();
    });
    card.querySelector(".issue-delete").addEventListener("click", async () => {
      if (!canDeleteProjectActivityEntries()) return;
      if (!confirm("이 이슈를 삭제할까요?")) return;
      const liveProject = selectedProject()?.id === project.id ? selectedProject() : project;
      liveProject.issues = (liveProject.issues || []).filter((item) => item.id !== issue.id);
      if (editingIssueId === issue.id) editingIssueId = "";
      await persistEntry();
      renderIssues(selectedProject() || liveProject);
      renderIssueProjectRows();
    });

    if (isEditing) textarea.focus();
  });

  applyReadOnlyUi();
}

function requireDetailField(id, message) {
  const value = valueOf(id).trim();
  if (value !== "") return value;
  openDetailDropdowns();
  setText("saveState", message);
  $(id)?.focus();
  return null;
}

function applyDetailFormToProject(project) {
  if (!String(project.projectNo || "").trim()) project.projectNo = nextProjectNo();
  setValue("projectNo", project.projectNo);
  const projectNoRaw = String(project.projectNo || valueOf("projectNo")).trim();
  const projectNo = projectNoRaw.replace(/\D/g, "");
  if ($("projectNo") && $("projectNo").value !== projectNo) $("projectNo").value = projectNo;
  if (!projectNo) {
    openDetailDropdowns();
    setText("saveState", "PJ No를 입력해 주세요.");
    $("projectNo")?.focus();
    return null;
  }
  if (!/^\d+$/.test(projectNo)) {
    openDetailDropdowns();
    setText("saveState", "PJ No는 숫자만 입력할 수 있습니다.");
    $("projectNo")?.focus();
    return null;
  }

  const name = requireDetailField("name", "프로젝트명을 입력해 주세요.");
  if (name === null) return null;
  const contractDate = requireDetailField("contractDate", "계약일을 입력해 주세요.");
  if (contractDate === null) return null;
  const dueDate = requireDetailField("dueDate", "납기일을 입력해 주세요.");
  if (dueDate === null) return null;
  const contractAmount = requireDetailField("contractAmount", "총 계약금액을 입력해 주세요.");
  if (contractAmount === null) return null;
  const balance = requireDetailField("balance", "잔금을 입력해 주세요.");
  if (balance === null) return null;

  editableFields.forEach((field) => {
    project[field] = valueOf(field);
  });
  project.projectNo = projectNo;
  project.name = name;
  project.contractDate = contractDate;
  project.dueDate = dueDate;
  project.contractAmount = contractAmount;
  project.balance = balance;
  project.shortcutUrl = normalizeShortcutUrl(project.shortcutUrl);
  project.intranetUrl = normalizeShortcutUrl(project.intranetUrl);
  project.designUrl = normalizeShortcutUrl(project.designUrl);
  applyProjectStaffIds(project);
  project.hostingType = document.querySelector('[name="hostingType"]:checked')?.value || "일반 웹호스팅";
  project.hasForeignLanguage = checkedOf("hasForeignLanguage");
  project.monthlyCollection = checkedOf("monthlyCollection");
  project.hasIssue = checkedOf("hasIssue");
  const selectedLandingType = document.querySelector('[name="hasLanding"]:checked')?.value;
  project.hasLanding = selectedLandingType ? selectedLandingType === "landing" : checkedOf("hasLanding");
  return project;
}

async function saveDetail() {
  if (!requireWritableAction()) return;
  const creating = Boolean(isCreatingProject && draftProject);
  const project = creating ? draftProject : selectedProject();
  if (!project) {
    setText("saveState", "저장할 프로젝트가 없습니다.");
    return;
  }
  if (!applyDetailFormToProject(project)) return;
  if (currentUser && isDepartment("pm")) {
    project.pm = currentPmName();
    project.pmId = assignedProjectUserId();
  }

  if (creating) {
    if (!projects.some((item) => item.id === project.id)) {
      project.no = projects.length + 1;
      projects.unshift(project);
    }
    selectedId = project.id;
    isCreatingProject = false;
    draftProject = null;
  }

  projects = projects.filter(hasProjectNo);
  if (selectedId && !accessibleProjects().some((item) => item.id === selectedId)) {
    selectedId = accessibleProjects()[0]?.id || null;
  }
  if (!projects.some((item) => item.id === project.id)) {
    setText("saveState", "PJ No를 입력해 주세요.");
    return;
  }

  await persist();
  renderFilters();
  renderAll(false);
  setText("saveState", "저장되었습니다.");
  alert("프로젝트 상세가 저장되었습니다.");
}

function renderClientContacts(project) {
  const list = $("clientContactList");
  if (!list) return;
  project.clientContacts = project.clientContacts || [];
  if (!project.clientContacts.length) {
    list.innerHTML = '<p class="empty">등록된 고객 담당자가 없습니다.</p>';
    return;
  }

  list.innerHTML = project.clientContacts
    .map((contact) => {
      const isEditing = contact.id === editingContactId;
      return `
        <article class="contact-card" data-contact-id="${contact.id}">
          <div class="contact-view ${isEditing ? "hidden" : ""}">
            <div class="entry-view-grid">
              <div><span class="entry-field-label">이름</span><div class="entry-field-value">${escapeHtml(contact.name || "-")}</div></div>
              <div><span class="entry-field-label">회사 연락처</span><div class="entry-field-value">${escapeHtml(contact.companyPhone || "-")}</div></div>
              <div><span class="entry-field-label">개인 연락처</span><div class="entry-field-value">${escapeHtml(contact.personalPhone || "-")}</div></div>
              <div><span class="entry-field-label">이메일</span><div class="entry-field-value">${escapeHtml(contact.email || "-")}</div></div>
            </div>
            <div class="issue-actions">
              <button class="ghost-btn contact-edit" type="button">수정</button>
              <button class="ghost-btn danger contact-delete" type="button">삭제</button>
            </div>
          </div>
          <div class="issue-edit-panel ${isEditing ? "" : "hidden"}">
            <div class="entry-edit-grid">
              <label>이름<input class="contact-name" value="${escapeAttr(contact.name || "")}" /></label>
              <label>회사 연락처<input class="contact-company-phone" inputmode="numeric" maxlength="13" value="${escapeAttr(formatClientPhone(contact.companyPhone || ""))}" /></label>
              <label>개인 연락처<input class="contact-personal-phone" inputmode="numeric" maxlength="13" value="${escapeAttr(formatClientPhone(contact.personalPhone || ""))}" /></label>
              <label>이메일<input class="contact-email" type="email" value="${escapeAttr(contact.email || "")}" /></label>
            </div>
            <div class="issue-actions">
              <button class="primary-btn contact-save" type="button">저장</button>
              <button class="ghost-btn contact-cancel" type="button">취소</button>
            </div>
          </div>
        </article>
      `;
    })
    .join("");

  list.querySelectorAll(".contact-card").forEach((card) => {
    const contact = project.clientContacts.find((item) => item.id === card.dataset.contactId);
    if (!contact) return;
    const view = card.querySelector(".contact-view");
    const editPanel = card.querySelector(".issue-edit-panel");
    const nameInput = card.querySelector(".contact-name");
    const companyInput = card.querySelector(".contact-company-phone");
    const personalInput = card.querySelector(".contact-personal-phone");
    const emailInput = card.querySelector(".contact-email");
    const isEditing = contact.id === editingContactId;

    const fillInputs = () => {
      nameInput.value = contact.name || "";
      companyInput.value = formatClientPhone(contact.companyPhone || "");
      personalInput.value = formatClientPhone(contact.personalPhone || "");
      emailInput.value = contact.email || "";
    };

    bindClientPhoneInput(companyInput);
    bindClientPhoneInput(personalInput);

    card.querySelector(".contact-edit").addEventListener("click", () => {
      editingContactId = contact.id;
      fillInputs();
      view.classList.add("hidden");
      editPanel.classList.remove("hidden");
      nameInput.focus();
    });
    card.querySelector(".contact-cancel").addEventListener("click", () => {
      if (isBlankContact(contact)) {
        project.clientContacts = project.clientContacts.filter((item) => item.id !== contact.id);
        editingContactId = "";
        persistEntry();
        renderClientContacts(project);
        return;
      }
      editingContactId = "";
      fillInputs();
      editPanel.classList.add("hidden");
      view.classList.remove("hidden");
    });
    card.querySelector(".contact-save").addEventListener("click", async () => {
      contact.name = nameInput.value.trim();
      contact.companyPhone = formatClientPhone(companyInput.value);
      contact.personalPhone = formatClientPhone(personalInput.value);
      contact.email = emailInput.value.trim();
      editingContactId = "";
      await persistEntry();
      renderClientContacts(project);
    });
    card.querySelector(".contact-delete").addEventListener("click", async () => {
      project.clientContacts = project.clientContacts.filter((item) => item.id !== contact.id);
      if (editingContactId === contact.id) editingContactId = "";
      await persistEntry();
      renderClientContacts(project);
    });

    if (isEditing) {
      fillInputs();
      nameInput.focus();
    }
  });
}


function projectWorkStackEntries(project) {
  return normalizeProjectCompletionFlow(project?.completionFlow).history.sort((a, b) => {
    const atA = a.at || "";
    const atB = b.at || "";
    if (atA === atB) return String(b.id).localeCompare(String(a.id));
    return atA < atB ? 1 : -1;
  });
}

function projectWorkStackStageLabel(entry) {
  const labels = {
    design_worker: "담당자 디자인 완료",
    design_lead: "팀장 디자인 완료",
    design_pm: "PM 디자인 완료",
    publishing_worker: "담당자 퍼블리싱 완료",
    publishing_lead: "팀장 퍼블리싱 완료",
    publishing_pm: "PM 퍼블리싱 완료",
    program_worker: "담당자 프로그램 완료",
    program_lead: "팀장 프로그램 완료",
    program_pm: "PM 프로그램 완료",
  };
  const key = String(entry?.action || "approve") === "reject" ? String(entry?.rejectedStage || entry?.stage || "") : String(entry?.stage || "");
  const label = labels[key] || String(entry?.label || "").replace(/\?+/g, "").trim() || projectCompletionTypeShortLabel(entry?.completionType) || "작업 완료";
  return String(entry?.action || "approve") === "reject" ? `${label} 반려` : label;
}

function projectWorkStackType(entry) {
  const completionType = String(entry?.completionType || "").trim().toLowerCase();
  if (["design", "publishing", "program"].includes(completionType)) return completionType;
  const key = String(entry?.rejectedStage || entry?.stage || "");
  if (key.startsWith("design_")) return "design";
  if (key.startsWith("publishing_")) return "publishing";
  if (key.startsWith("program_")) return "program";
  return "";
}

function projectWorkStackDepartmentNames(entry) {
  const type = projectWorkStackType(entry);
  if (type === "design") return ["디자인", "디자이너"];
  if (type === "publishing") return ["퍼블리싱", "퍼블리셔"];
  if (type === "program") return ["프로그램", "프로그래머"];
  return [];
}

function departmentColorByNames(names, fallback = "#ccfbf1") {
  const departments = projectRepository.getDepartments?.() || [];
  const normalizedNames = names.map((name) => normalizeDepartmentKey(name));
  const department = departments.find((item) => normalizedNames.includes(normalizeDepartmentKey(item.name)));
  return normalizeColorValue(department?.color, fallback);
}

function hexToRgba(hex, alpha = 1) {
  const color = normalizeColorValue(hex, "#ccfbf1").replace("#", "");
  const r = parseInt(color.slice(0, 2), 16);
  const g = parseInt(color.slice(2, 4), 16);
  const b = parseInt(color.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function projectWorkStackBadgeStyle(entry) {
  if (isRejectedWorkStackEntry(entry)) return "";
  const color = departmentColorByNames(projectWorkStackDepartmentNames(entry));
  return ` style="background:${escapeAttr(color)}; border-color:${escapeAttr(hexToRgba(color, 0.55))}; color:#111827;"`;
}

function projectWorkStackDisplayText(project, entry) {
  const defaultLabel = projectWorkStackStageLabel(entry);
  const actor = String(entry?.userName || "").trim();
  return [actor, defaultLabel].filter(Boolean).join(" / ") || defaultLabel;
}

function projectWorkStackReasonText(entry) {
  return String(entry?.reason || "").trim();
}

function projectWorkStackMemoText(entry) {
  const memo = String(entry?.memo || "").trim();
  if (!memo || ["design", "publishing", "program"].includes(memo)) return "";
  return memo;
}

function isRejectedWorkStackEntry(entry) {
  return String(entry?.action || "approve") === "reject";
}

function renderProjectWorkStack(project) {
  const list = $("projectWorkStackList");
  if (!list) return;
  const flow = normalizeProjectCompletionFlow(project?.completionFlow);
  project.completionFlow = flow;
  const allEntries = projectWorkStackEntries(project);
  const entries = allEntries.filter(
    (entry) =>
      entry.id === editingProjectWorkStackId ||
      matchesDetailSearch(entry.at, entry.label, entry.userName, entry.memo, projectWorkStackDisplayText(project, entry))
  );
  if (!allEntries.length) {
    list.innerHTML = '<p class="empty">\ub4f1\ub85d\ub41c \uc791\uc5c5 \uc2a4\ud0dd\uc774 \uc5c6\uc2b5\ub2c8\ub2e4.</p>';
    return;
  }
  if (!entries.length) {
    list.innerHTML = '<p class="empty">\uac80\uc0c9 \uacb0\uacfc\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.</p>';
    return;
  }
  list.innerHTML = entries
    .map((entry) => {
      const isEditing = entry.id === editingProjectWorkStackId;
      const displayText = projectWorkStackDisplayText(project, entry);
      const reasonText = projectWorkStackReasonText(entry);
      const memoText = projectWorkStackMemoText(entry);
      const rejected = isRejectedWorkStackEntry(entry);
      const badgeStyle = projectWorkStackBadgeStyle(entry);
      return `
        <article class="communication-card project-work-stack-card" data-work-stack-id="${escapeAttr(entry.id)}">
          <div class="communication-view ${isEditing ? "hidden" : ""}">
            <div class="entry-card-head">
              <div class="project-work-stack-head entry-card-head-main">
                <span class="project-schedule-date">${escapeHtml(entry.at || "-")}</span>
                <span class="schedule-staff-badge ${rejected ? "is-rejected" : ""}"${badgeStyle}>${escapeHtml(displayText)}</span>
                ${memoText ? `<span class="project-work-stack-memo-text">${escapeHtml(memoText)}</span>` : ""}
                ${reasonText ? `<span class="project-work-stack-reason ${rejected ? "is-rejected" : ""}">${escapeHtml(reasonText)}</span>` : ""}
              </div>
              <div class="entry-card-head-actions ${isAdmin() ? "" : "hidden"}">
                <button class="ghost-btn work-stack-edit" type="button">수정</button>
                <button class="ghost-btn danger work-stack-delete" type="button">삭제</button>
              </div>
            </div>
          </div>
          <div class="issue-edit-panel ${isEditing ? "" : "hidden"}">
            <div class="communication-edit-grid">
              <label>일시<input class="work-stack-at" type="datetime-local" value="${escapeAttr(toDateTimeLocalValue(entry.at))}" /></label>
              <textarea class="work-stack-memo" placeholder="작업 스택 내용을 입력하세요.">${escapeHtml(String(entry.memo || "").trim())}</textarea>
            </div>
            <div class="issue-actions">
              <button class="primary-btn work-stack-save" type="button">저장</button>
              <button class="ghost-btn work-stack-cancel" type="button">취소</button>
            </div>
          </div>
        </article>`;
    })
    .join("");

  list.querySelectorAll(".project-work-stack-card").forEach((card) => {
    const entry = allEntries.find((item) => item.id === card.dataset.workStackId);
    if (!entry) return;
    const view = card.querySelector(".communication-view");
    const editPanel = card.querySelector(".issue-edit-panel");
    const atInput = card.querySelector(".work-stack-at");
    const memoInput = card.querySelector(".work-stack-memo");
    card.querySelector(".work-stack-edit")?.addEventListener("click", () => {
      if (!isAdmin()) return;
      editingProjectWorkStackId = entry.id;
      renderProjectWorkStack(project);
    });
    card.querySelector(".work-stack-cancel")?.addEventListener("click", () => {
      editingProjectWorkStackId = "";
      editPanel.classList.add("hidden");
      view.classList.remove("hidden");
      renderProjectWorkStack(project);
    });
    card.querySelector(".work-stack-save")?.addEventListener("click", () => {
      if (!isAdmin()) return;
      entry.at = fromDateTimeLocalValue(atInput.value) || entry.at || "";
      entry.memo = memoInput.value.trim();
      editingProjectWorkStackId = "";
      persistEntry();
      renderProjectWorkStack(project);
    });
    card.querySelector(".work-stack-delete")?.addEventListener("click", () => {
      if (!isAdmin()) return;
      project.completionFlow.history = project.completionFlow.history.filter((item) => item.id !== entry.id);
      editingProjectWorkStackId = "";
      persistEntry();
      renderProjectWorkStack(project);
    });
  });
}

function toDateTimeLocalValue(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  const normalized = text.replace(" ", "T").slice(0, 16);
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(normalized) ? normalized : "";
}

function fromDateTimeLocalValue(value) {
  const text = String(value || "").trim();
  return text ? text.replace("T", " ") + (text.length === 16 ? ":00" : "") : "";
}

function renderCommunications(project) {
  const list = $("communicationList");
  if (!list) return;
  project.communications = (project.communications || []).sort((a, b) => {
    const dateA = a.date || "";
    const dateB = b.date || "";
    if (dateA === dateB) return String(b.id).localeCompare(String(a.id));
    return dateA < dateB ? 1 : -1;
  });
  const allEntries = project.communications;
  const entries = allEntries.filter(
    (entry) => entry.id === editingCommunicationId || matchesDetailSearch(entry.date, entry.memo)
  );
  if (!allEntries.length) {
    list.innerHTML = '<p class="empty">등록된 소통내역이 없습니다.</p>';
    return;
  }
  if (!entries.length) {
    list.innerHTML = '<p class="empty">검색 결과가 없습니다.</p>';
    return;
  }

  list.innerHTML = entries
    .map((entry) => {
      const isEditing = entry.id === editingCommunicationId;
      const dateText = entry.date || todayDate();
      const memoText = entry.memo || "";
      return `
        <article class="communication-card" data-communication-id="${entry.id}">
          <div class="communication-view ${isEditing ? "hidden" : ""}">
            <p class="entry-meta">${escapeHtml(entryAuthorName(entry))} ${escapeHtml(dateText)}</p>
            <p class="issue-text">${escapeHtml(memoText || "내용 없음")}</p>
            <div class="issue-actions">
              <button class="ghost-btn communication-edit" type="button">수정</button>
              <button class="ghost-btn danger communication-delete" type="button">삭제</button>
            </div>
          </div>
          <div class="issue-edit-panel ${isEditing ? "" : "hidden"}">
            <div class="communication-edit-grid">
              <label>일자<input class="communication-date" type="date" value="${escapeAttr(dateText)}" /></label>
              <textarea class="communication-memo" placeholder="프로젝트 관련 소통 내용을 기록하세요.">${escapeHtml(memoText)}</textarea>
            </div>
            <div class="issue-actions">
              <button class="primary-btn communication-save" type="button">저장</button>
              <button class="ghost-btn communication-cancel" type="button">취소</button>
            </div>
          </div>
        </article>
      `;
    })
    .join("");

  list.querySelectorAll(".communication-card").forEach((card) => {
    const entry = allEntries.find((item) => item.id === card.dataset.communicationId);
    if (!entry) return;
    const view = card.querySelector(".communication-view");
    const editPanel = card.querySelector(".issue-edit-panel");
    const dateInput = card.querySelector(".communication-date");
    const memoInput = card.querySelector(".communication-memo");
    const isEditing = entry.id === editingCommunicationId;

    const fillInputs = () => {
      dateInput.value = entry.date || todayDate();
      memoInput.value = entry.memo || "";
    };

    card.querySelector(".communication-edit").addEventListener("click", () => {
      if (!canEditProjectCommunications()) return;
      editingCommunicationId = entry.id;
      fillInputs();
      view.classList.add("hidden");
      editPanel.classList.remove("hidden");
      memoInput.focus();
    });
    card.querySelector(".communication-cancel").addEventListener("click", () => {
      if (!canEditProjectCommunications()) return;
      if (!String(entry.memo || "").trim()) {
        project.communications = project.communications.filter((item) => item.id !== entry.id);
        editingCommunicationId = "";
        persistEntry();
        renderCommunications(project);
        return;
      }
      editingCommunicationId = "";
      fillInputs();
      editPanel.classList.add("hidden");
      view.classList.remove("hidden");
    });
    card.querySelector(".communication-save").addEventListener("click", () => {
      if (!canEditProjectCommunications()) return;
      entry.date = dateInput.value || todayDate();
      entry.memo = memoInput.value.trim();
      editingCommunicationId = "";
      persistEntry();
      renderCommunications(project);
    });
    card.querySelector(".communication-delete").addEventListener("click", () => {
      if (!canDeleteProjectActivityEntries()) return;
      project.communications = project.communications.filter((item) => item.id !== entry.id);
      if (editingCommunicationId === entry.id) editingCommunicationId = "";
      persistEntry();
      renderCommunications(project);
    });

    if (isEditing) memoInput.focus();
  });
}

function addProject() {
  if (!canCreateProject()) {
    alert("프로젝트 추가는 영업 부서만 할 수 있습니다.");
    return;
  }
  isCreatingProject = true;
  draftProject = createEmptyProject();
  if (currentUser && isDepartment("pm")) {
    draftProject.pm = currentPmName();
  }
  selectedId = null;
  editingIssueId = "";
  editingContactId = "";
  editingCommunicationId = "";

  if (currentView !== "projects") {
    currentView = "projects";
    activateViewPanel("projects");
  }

  document.body.classList.remove("schedule-detail-open");
  document.body.classList.add("detail-open");
  openDetailDropdowns();
  renderRows();
  renderDetail();
  saveUiSessionState();
  $("name")?.focus();
}

function deleteSelectedProject() {
  if (!requireWritableAction()) return;
  if (isCreatingProject) {
    closeDetail();
    return;
  }
  if (!isAdmin()) {
    setText("saveState", "삭제는 관리자만 할 수 있습니다.");
    return;
  }
  const project = selectedProject();
  if (!project) return;
  const label = project.name || project.projectNo || "이 프로젝트";
  if (!confirm(`"${label}" 프로젝트를 삭제할까요?`)) return;
  projects = projects.filter((item) => item.id !== project.id);
  selectedId = accessibleProjects()[0]?.id || null;
  document.body.classList.remove("detail-open", "schedule-detail-open");
  void persist();
  renderFilters();
  activateViewPanel(currentView);
  renderAll();
  saveUiSessionState();
  syncProjectsPersistSnapshot(projects);
  if (isAdmin()) void refreshLoginLogs();
  if (currentUser) void refreshProjectLogs();
}

function addIssue() {
  if (!requireWritableAction()) return;
  if (!canEditProjectIssues()) return;
  const project = selectedProject();
  if (!project) return;
  project.issues = project.issues || [];
  const id = crypto.randomUUID();
  project.issues.unshift(
    normalizeIssue({
      id,
      status: "",
      type: "",
      memo: "",
      date: todayDate(),
      createdAt: new Date().toISOString(),
      createdById: assignedProjectUserId(),
      createdByName: assignedProjectUserName(),
      resolved: false,
    })
  );
  editingIssueId = id;
  if (!isCreatingProject) void persist();
  renderIssues(project);
}

function addClientContact() {
  if (!requireWritableAction()) return;
  if (!canEditProjectActivity() && !isCreatingProject) return;
  const project = selectedProject();
  if (!project) return;
  project.clientContacts = project.clientContacts || [];
  const id = crypto.randomUUID();
  project.clientContacts.unshift({
    id,
    name: "",
    companyPhone: "",
    personalPhone: "",
    email: "",
  });
  editingContactId = id;
  renderClientContacts(project);
}

function addCommunication() {
  if (!requireWritableAction()) return;
  if (!canEditProjectCommunications()) return;
  const project = selectedProject();
  if (!project) return;
  project.communications = project.communications || [];
  const id = crypto.randomUUID();
  project.communications.unshift({
    id,
    date: todayDate(),
    memo: "",
    createdById: assignedProjectUserId(),
    createdByName: assignedProjectUserName(),
  });
  editingCommunicationId = id;
  if (!isCreatingProject) void persist();
  renderCommunications(project);
}

const MAX_UPLOAD_PDF_BYTES = 10 * 1024 * 1024;
const PDF_DANGEROUS_TEXT_PATTERNS = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA"];

async function inspectPdfUpload(file) {
  if (!file) return { ok: false, message: "파일을 선택해 주세요." };
  if (file.type && file.type !== "application/pdf") {
    return { ok: false, message: "PDF 파일만 업로드할 수 있습니다." };
  }
  if (!file.name.toLowerCase().endsWith(".pdf")) {
    return { ok: false, message: "PDF 확장자 파일만 업로드할 수 있습니다." };
  }
  if (file.size > MAX_UPLOAD_PDF_BYTES) {
    return { ok: false, message: "PDF 파일은 10MB 이하만 업로드할 수 있습니다." };
  }

  const bytes = new Uint8Array(await file.slice(0, Math.min(file.size, 2 * 1024 * 1024)).arrayBuffer());
  const signature = new TextDecoder("latin1").decode(bytes.slice(0, 5));
  if (signature !== "%PDF-") {
    return { ok: false, message: "정상 PDF 파일이 아닙니다." };
  }

  const scanText = new TextDecoder("latin1").decode(bytes).toLowerCase();
  const hasDangerousPattern = PDF_DANGEROUS_TEXT_PATTERNS.some((pattern) => scanText.includes(pattern.toLowerCase()));
  if (hasDangerousPattern) {
    return { ok: false, message: "보안상 위험한 PDF 기능이 포함되어 업로드할 수 없습니다." };
  }
  return { ok: true };
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error("파일을 읽을 수 없습니다."));
    reader.readAsDataURL(file);
  });
}

async function handlePdfUpload(event) {
  if (!canManageProjectQuote() || !requireWritableAction()) {
    quoteUploadProjectId = "";
    if (event?.target) event.target.value = "";
    if (!canManageProjectQuote()) alert("현재 계정은 견적서를 등록할 권한이 없습니다.");
    return;
  }
  const file = event.target.files?.[0];
  const project = quoteUploadProjectId ? findProjectById(quoteUploadProjectId) : selectedProject();
  if (!project || !file) {
    quoteUploadProjectId = "";
    event.target.value = "";
    return;
  }

  const inspection = await inspectPdfUpload(file);
  if (!inspection.ok) {
    alert(inspection.message);
    quoteUploadProjectId = "";
    event.target.value = "";
    return;
  }

  try {
    project.quoteFileName = file.name;
    project.quoteFileData = await readFileAsDataUrl(file);
    if (!isCreatingProject) await persist();
    quoteUploadProjectId = "";
    event.target.value = "";
    renderRows();
    if (isCreatingProject || selectedId === project.id) renderDetail();
  } catch (error) {
    console.error(error);
    alert("파일을 업로드할 수 없습니다. 다른 PDF 파일로 다시 시도해 주세요.");
    project.quoteFileName = "";
    project.quoteFileData = "";
    quoteUploadProjectId = "";
    event.target.value = "";
  }
}

function handleQuoteAction() {
  const project = selectedProject();
  if (project?.quoteFileData) {
    viewQuoteForProject(project);
    return;
  }
  if (!canManageProjectQuote()) {
    alert("현재 계정은 견적서를 등록할 권한이 없습니다.");
    return;
  }
  quoteUploadProjectId = "";
  $("quoteFile")?.click();
}

function downloadStamp() {
  return todayDate();
}

function triggerDownload(blob, filename) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function openDownloadDialog() {
  const excelOption = document.querySelector('input[name="downloadType"][value="excel"]');
  if (excelOption) excelOption.checked = true;
  $("downloadDialog")?.showModal();
}

function closeDownloadDialog() {
  $("downloadDialog")?.close();
}

function submitDownloadForm(event) {
  event.preventDefault();
  const type = document.querySelector('input[name="downloadType"]:checked')?.value || "excel";
  if (type === "json") downloadProjectsJson();
  else downloadProjectsExcel();
  closeDownloadDialog();
}

function downloadProjectsJson() {
  const payload = {
    exportedAt: new Date().toISOString(),
    projects: accessibleProjects(),
    adminProjects: isAdmin() ? adminProjects : [],
    users: isAdmin() && typeof projectRepository.getUsers === "function" ? projectRepository.getUsers() : [],
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  triggerDownload(blob, `프로젝트_전체데이터_${downloadStamp()}.json`);
}

function escapeXml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function excelCell(value, type = "String") {
  if (value === null || value === undefined || value === "") {
    return `<Cell><Data ss:Type="String"></Data></Cell>`;
  }
  if (type === "Number" && Number.isFinite(Number(value))) {
    return `<Cell><Data ss:Type="Number">${Number(value)}</Data></Cell>`;
  }
  return `<Cell><Data ss:Type="String">${escapeXml(value)}</Data></Cell>`;
}

function projectDetailExcelRow(project) {
  return [
    excelCell(project.projectNo),
    excelCell(project.name),
    excelCell(project.industry),
    excelCell(project.contractDate),
    excelCell(project.dueDate),
    excelCell(project.openDate),
    excelCell(project.contractAmount, "Number"),
    excelCell(project.balance, "Number"),
    excelCell(project.depositDate),
    excelCell(project.shortcutUrl),
    excelCell(project.intranetUrl),
    excelCell(project.designUrl),
    excelCell(project.milestone),
    excelCell(project.status || project.progressStatus),
    excelCell(project.pm),
    excelCell(project.designer),
    excelCell(project.publisher),
    excelCell(project.programmer),
    excelCell(project.hostingType || "일반 웹호스팅"),
    excelCell(project.hasLanding ? "랜딩" : "일반형"),
    excelCell(project.hasForeignLanguage ? "Y" : "N"),
    excelCell(project.monthlyCollection ? "Y" : "N"),
  ].join("");
}

function downloadProjectsExcel() {
  const rows = accessibleProjects().filter(hasProjectNo);
  if (!rows.length) {
    alert("다운로드할 프로젝트가 없습니다.");
    return;
  }

  const headers = [
    "PJ No",
    "프로젝트명",
    "업종",
    "계약일",
    "납기일",
    "오픈일자",
    "총 계약금액",
    "잔금",
    "입금일",
    "홈페이지 URL",
    "인트라 URL",
    "화면설계 URL",
    "마일스톤",
    "작업상태",
    "PM",
    "디자이너",
    "퍼블리셔",
    "프로그래머",
    "호스팅",
    "랜딩",
    "외국어",
    "당월수금",
  ];

  const headerRow = `<Row>${headers.map((header) => excelCell(header)).join("")}</Row>`;
  const dataRows = rows.map((project) => `<Row>${projectDetailExcelRow(project)}</Row>`).join("");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:html="http://www.w3.org/TR/REC-html40">
 <Worksheet ss:Name="프로젝트 상세">
  <Table>
   ${headerRow}
   ${dataRows}
  </Table>
 </Worksheet>
</Workbook>`;

  const blob = new Blob([`\uFEFF${xml}`], { type: "application/vnd.ms-excel;charset=utf-8;" });
  triggerDownload(blob, `프로젝트_상세_${downloadStamp()}.xls`);
}

function openLogin() {
  setText("loginMessage", "");
  if (!currentUser) {
    setValue("loginId", "");
    setValue("loginPassword", "");
  }
  const dialog = $("loginDialog");
  if (dialog && !dialog.open) dialog.showModal();
}

function applyLoginGate() {
  const locked = !currentUser;
  document.body.classList.toggle("auth-locked", locked);
  $("closeLogin")?.classList.toggle("hidden", locked);
  const dialog = $("loginDialog");
  if (locked) {
    setText("loginMessage", "");
    if (dialog && !dialog.open) dialog.showModal();
    return;
  }
  if (dialog?.open) dialog.close();
}

const PASSWORD_POLICY_MESSAGE = "비밀번호는 알파벳, 숫자, 특수문자를 포함해 8자 이상이어야 합니다.";

function isValidPassword(password) {
  const value = String(password || "");
  return value.length >= 8 && /[A-Za-z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}

let memberDialogMode = "create";
let editingMemberId = "";
const POSITION_OPTIONS = ["사원", "주임", "대리", "과장", "차장", "부장", "이사", "상무", "대표"];
const MEMBER_DEPARTMENT_EXCLUDED_NAMES = new Set(["유지보수"]);

function memberDepartmentOptionsSource() {
  // 현재 프로젝트 범위에서는 회원 부서 선택지에서 유지보수를 제외한다.
  return (projectRepository.getDepartments?.() || []).filter((department) => !MEMBER_DEPARTMENT_EXCLUDED_NAMES.has(department.name || ""));
}

function departmentOptions(selected = "") {
  const departments = memberDepartmentOptionsSource();
  return departments
    .map((department) => {
      const name = department.name || "";
      return `<option value="${escapeAttr(name)}" ${name === selected ? "selected" : ""}>${escapeHtml(name)}</option>`;
    })
    .join("");
}

function positionOptions(selected = "") {
  const value = String(selected || "").trim();
  const options = value && !POSITION_OPTIONS.includes(value) ? [...POSITION_OPTIONS, value] : POSITION_OPTIONS;
  return `<option value="">선택</option>` + options
    .map((position) => `<option value="${escapeAttr(position)}" ${position === value ? "selected" : ""}>${escapeHtml(position)}</option>`)
    .join("");
}

function populatePositionSelect(selected = "") {
  const select = $("memberPosition");
  if (!select) return;
  select.innerHTML = positionOptions(selected);
  select.value = String(selected || "").trim();
}

function normalizeColorValue(value, fallback = "#d9eadf") {
  const color = String(value || "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(color) ? color.toLowerCase() : fallback;
}

function departmentColor(name) {
  const department = (projectRepository.getDepartments?.() || []).find((item) => item.name === name);
  return normalizeColorValue(department?.color);
}

function departmentEventStyle(name) {
  return ` style="background:${escapeAttr(departmentColor(name))}"`;
}

function populateDepartmentSelect(selectId, selected = "") {
  const select = $(selectId);
  if (!select) return;
  select.innerHTML = departmentOptions(selected);
  if (!select.value && select.options.length) select.selectedIndex = 0;
}

function openMemberDialog(memberId = "") {
  if (!isAdmin()) return;
  const isEdit = Boolean(memberId);
  memberDialogMode = isEdit ? "edit" : "create";
  editingMemberId = isEdit ? memberId : "";

  const user = isEdit ? projectRepository.getUsers().find((item) => item.id === memberId) : null;
  if (isEdit && !user) {
    alert("회원을 찾을 수 없습니다.");
    return;
  }

  setText("memberDialogTitle", isEdit ? "회원 상세" : "회원 추가");
  setText("memberSubmitBtn", isEdit ? "저장" : "등록");
  setValue("memberId", user?.id || "");
  setValue("memberName", user?.name || "");
  populatePositionSelect(user?.position || "");
  setValue("memberHireDate", user?.hireDate || "");
  setValue("memberResignDate", user?.resignDate || "");
  populateDepartmentSelect("memberDepartment", user?.department || "");
  setValue("memberRole", ["admin", "team_lead", "user"].includes(user?.role) ? user.role : "user");
  setValue("memberApproval", user?.approvalStatus || "비활성화");
  setValue("memberPassword", "");
  setValue("memberPasswordConfirm", "");
  setText("memberMessage", "");

  const idInput = $("memberId");
  if (idInput) {
    idInput.readOnly = isEdit;
    idInput.classList.toggle("is-readonly", isEdit);
  }

  setText("memberPasswordTitle", isEdit ? "비밀번호 변경" : "비밀번호");
  if ($("memberPassword")) {
    $("memberPassword").placeholder = isEdit
      ? "알파벳+숫자+특수문자 8자 이상 (변경 시)"
      : "알파벳+숫자+특수문자 8자 이상";
  }
  if ($("memberPasswordConfirm")) {
    $("memberPasswordConfirm").placeholder = "비밀번호 확인";
  }
  $("memberPasswordConfirmWrap")?.classList.toggle("hidden", !isEdit);

  const locked = isEdit && user?.id === "admin";
  if ($("memberRole")) $("memberRole").disabled = locked;
  if ($("memberApproval")) $("memberApproval").disabled = locked;

  $("memberDialog")?.showModal();
  (isEdit ? $("memberName") : $("memberId"))?.focus();
}

function closeMemberDialog() {
  memberDialogMode = "create";
  editingMemberId = "";
  $("memberDialog")?.close();
}

function updateStateFromSnapshot(snapshot = {}, options = {}) {
  projects = (snapshot.projects || []).map(normalizeProject).filter(hasProjectNo);
  scheduleProjects = (snapshot.scheduleProjects || snapshot.projects || []).map(normalizeProject).filter(hasProjectNo);
  assignmentProjects = (snapshot.assignmentProjects || snapshot.projects || []).map(normalizeProject).filter(hasProjectNo);
  adminProjects = (snapshot.adminProjects || []).filter((project) => project.projectNo);
  loginUser = snapshot.loginUser || loginUser || "";
  currentUser = snapshot.currentUser || currentUser || null;
  mergeAdminFields();
  if (!options.keepSelected) selectedId = accessibleProjects()[0]?.id || null;
  else if (selectedId && !detailAccessibleProjects().some((project) => project.id === selectedId)) selectedId = accessibleProjects()[0]?.id || null;
  syncProjectsPersistSnapshot(projects);
}

async function applyDatasetMode(mode) {
  const snapshot = await projectRepository.loadDataset(mode);
  updateStateFromSnapshot(snapshot);
  cancelCreateProject();
  document.body.classList.remove("detail-open", "schedule-detail-open");
  updateAuthUi();
  renderAll();
}

async function submitLogin(event) {
  event.preventDefault();
  const id = valueOf("loginId").trim();
  const password = valueOf("loginPassword").trim();
  if (!id || !password) {
    setText("loginMessage", "아이디와 비밀번호를 입력하세요.");
    return;
  }
  try {
    const result = await projectRepository.authenticateUser(id, password);
    if (!result.ok) {
      setText("loginMessage", result.message || "아이디 또는 비밀번호가 올바르지 않습니다.");
      return;
    }
    currentUser = result.user;
    loginUser = result.user.id;
    updateAuthUi();
    setValue("loginId", "");
    setValue("loginPassword", "");
    setText("loginMessage", "");
    await applyDatasetMode("private");
    if (projects.length === 0) {
      await applyDatasetMode("private");
    }
    if (isAdmin()) {
      await refreshMemberManagementData();
      void refreshDepartments();
    }
  } catch (error) {
    console.error(error);
    setText("loginMessage", error.message || "서버에 연결할 수 없습니다. sqlite_server.py 실행 여부를 확인해 주세요.");
  }
}

function restoreLogin() {
  currentUser = loginUser ? projectRepository.findUser(loginUser) : null;
  if (loginUser && (!currentUser || currentUser.approvalStatus !== "활성화")) {
    projectRepository.clearLoginUser();
    loginUser = "";
    currentUser = null;
  }
  updateAuthUi();
}

async function logout() {
  loginUser = "";
  currentUser = null;
  projectRepository.clearLoginUser();
  updateAuthUi();
  await applyDatasetMode("public");
}

function updateAuthUi() {
  const loggedIn = Boolean(loginUser);
  const displayName = currentUser?.name || loginUser;
  setText("authStatus", loggedIn ? (isAdmin() ? "관리자 로그인" : `${displayName} 로그인`) : "로그인 전");
  $("loginButton")?.classList.toggle("hidden", loggedIn);
  $("logoutButton")?.classList.toggle("hidden", !loggedIn);
  applyLoginGate();
  updateNavAccess();
  applyReadOnlyUi();
}

async function submitMemberForm(event) {
  event.preventDefault();
  if (!isAdmin()) return;

  const name = valueOf("memberName").trim();
  const position = valueOf("memberPosition").trim();
  const hireDate = valueOf("memberHireDate").trim();
  const resignDate = valueOf("memberResignDate").trim();
  const role = valueOf("memberRole");
  const approvalStatus = valueOf("memberApproval");
  const department = valueOf("memberDepartment");
  const password = valueOf("memberPassword");
  const passwordConfirm = valueOf("memberPasswordConfirm");

  if (memberDialogMode === "edit") {
    if (!name) {
      setText("memberMessage", "이름을 입력해 주세요.");
      return;
    }
    if (password || passwordConfirm) {
      if (!password) {
        setText("memberMessage", "새 비밀번호를 입력해 주세요.");
        return;
      }
      if (!isValidPassword(password)) {
        setText("memberMessage", PASSWORD_POLICY_MESSAGE);
        return;
      }
      if (password !== passwordConfirm) {
        setText("memberMessage", "비밀번호 확인이 일치하지 않습니다.");
        return;
      }
    }

    const patch = { name, position, hireDate, resignDate, role, approvalStatus, department };
    if (password) patch.password = password;
    const result = await projectRepository.updateUser(editingMemberId, patch);
    setText("memberMessage", result.ok ? "회원 정보가 저장되었습니다." : result.message);
    if (!result.ok) return;

    if (editingMemberId === loginUser) {
      currentUser = result.user;
      updateAuthUi();
      if (result.user.approvalStatus !== "활성화") {
        closeMemberDialog();
        await logout();
        alert("계정이 비활성화되어 로그아웃되었습니다.");
        return;
      }
    }
    closeMemberDialog();
    renderBasicManagement();
    return;
  }

  if (!isValidPassword(password)) {
    setText("memberMessage", PASSWORD_POLICY_MESSAGE);
    return;
  }

  const result = await projectRepository.createUser({
    id: valueOf("memberId"),
    password,
    name,
    position,
    hireDate,
    resignDate,
    role,
    approvalStatus,
    department,
  });
  setText("memberMessage", result.message);
  if (!result.ok) return;
  closeMemberDialog();
  renderBasicManagement();
}

function approvalBadgeClass(status) {
  return status === "활성화" ? "approved" : "rejected";
}

function employmentStatusLabel(status) {
  return status === "활성화" ? "재직" : "퇴사";
}

function closeDetail() {
  cancelCreateProject();
  document.body.classList.remove("detail-open", "schedule-detail-open");
  renderAll(false);
  saveUiSessionState();
}

function openProjectDetailOnScheduleView(projectId) {
  const project = findProjectByScheduleInput(projectId);
  if (!project) return false;
  cancelCreateProject();
  selectedId = project.id;
  document.body.classList.add("detail-open", "schedule-detail-open");
  closeDetailDropdowns();
  renderDetail();
  openProjectScheduleDropdown();
  saveUiSessionState();
  return true;
}

function openProjectDetailFromSchedule(entryId) {
  const entry = allScheduleEntries().find((item) => item.id === entryId);
  if (!entry) return false;
  const project = findProjectByScheduleInput(entry.projectId);
  if (!project) return false;
  cancelCreateProject();
  selectedId = project.id;
  if (currentView !== "projects") {
    currentView = "projects";
    activateViewPanel("projects");
  }
  document.body.classList.remove("schedule-detail-open");
  document.body.classList.add("detail-open");
  closeDetailDropdowns();
  renderAll(false);
  openProjectScheduleDropdown();
  saveUiSessionState();
  return true;
}

function toggleSidebar() {
  document.body.classList.toggle("sidebar-collapsed");
  const collapsed = document.body.classList.contains("sidebar-collapsed");
  const label = collapsed ? "메뉴 열기" : "메뉴 접기";
  const rail = $("sidebarRail");
  const railIcon = document.querySelector(".sidebar-rail-icon");
  if (rail) {
    rail.setAttribute("aria-label", label);
    rail.title = label;
  }
  if (railIcon) railIcon.textContent = collapsed ? "›" : "‹";
  if (!collapsed) syncSidebarWidthToClock();
}

function statusOptions() {
  return workStatusOptions();
}

function openStatusDialog(projectId) {
  if (!requireWritableAction()) return;
  const project = projects.find((item) => item.id === projectId);
  if (!project) return;
  editingStatusProjectId = projectId;
  const current = project.progressStatus || project.status || "미지정";
  $("statusProjectName").textContent = `${project.projectNo} · ${project.name || "이름 없음"}`;
  $("statusSelect").innerHTML = statusOptions().map((status) => `<option value="${escapeAttr(status)}">${escapeHtml(status)}</option>`).join("");
  $("statusSelect").value = statusOptions().includes(current) ? current : "작업중";
  $("statusDialog").showModal();
}

async function submitStatusChange(event) {
  if (!requireWritableAction()) return;
  event.preventDefault();
  const project = projects.find((item) => item.id === editingStatusProjectId);
  if (!project) return;
  const nextStatus = $("statusSelect").value;
  project.progressStatus = nextStatus;
  project.status = nextStatus;
  const admin = adminProjects.find((item) => String(item.projectNo).trim() === String(project.projectNo).trim());
  if (admin) admin.progressStatus = nextStatus;
  await persist();
  projectRepository.saveAdminProjects(adminProjects);
  $("statusDialog").close();
  renderDashboard();
  renderRows();
  renderDetail();
}


async function refreshMemberManagementData() {
  if (!isAdmin()) return;
  try {
    if (typeof projectRepository?.refreshDepartments === "function") await projectRepository.refreshDepartments();
    if (typeof projectRepository?.refreshUsers === "function") await projectRepository.refreshUsers();
    renderBasicManagement();
  } catch (error) {
    console.error(error);
    renderBasicManagement();
  }
}

function renderBasicManagement() {
  if (!isAdmin()) return;
  const users = typeof projectRepository?.getUsers === "function" ? projectRepository.getUsers() : [];
  const inactiveUsers = users.filter((user) => user.approvalStatus !== "활성화");
  const activeUsers = users.filter((user) => user.approvalStatus === "활성화");
  setText("memberCount", users.length.toLocaleString("ko-KR"));
  setText("pendingMemberCount", inactiveUsers.length.toLocaleString("ko-KR"));
  setText("regularMemberCount", activeUsers.length.toLocaleString("ko-KR"));

  renderMemberDepartmentFilter();
  const filteredUsers = filterMembers(users);
  const rows = $("memberRows");
  if (!rows) return;
  rows.innerHTML =
    filteredUsers
      .map((user) => {
        const approval = user.approvalStatus || "비활성화";
        return `<tr data-member-id="${escapeAttr(user.id)}" class="member-row">
      <td>${escapeHtml(user.id)}</td>
      <td>${escapeHtml(user.name || "-")}</td>
      <td>${escapeHtml(user.department || "-")}</td>
      <td>${escapeHtml(user.position || "-")}</td>
      <td>${escapeHtml(formatLeaveDays(user.leaveTotalDays || 0))}</td>
      <td>${escapeHtml(formatLeaveDays(user.leaveRemainingDays || 0))}</td>
      <td><span class="role-badge ${roleBadgeClass(user.role)}">${escapeHtml(roleLabel(user.role))}</span></td>
      <td><span class="status-badge ${approvalBadgeClass(approval)}">${escapeHtml(employmentStatusLabel(approval))}</span></td>
    </tr>`;
      })
      .join("") || '<tr><td colspan="8" class="empty-cell">조회된 회원이 없습니다.</td></tr>';

  rows.querySelectorAll("tr.member-row").forEach((row) => {
    row.addEventListener("click", () => openMemberDialog(row.dataset.memberId));
  });
}

function renderMemberDepartmentFilter() {
  const select = $("memberDepartmentFilter");
  if (!select) return;
  const selected = select.value || "";
  const departments = memberDepartmentOptionsSource();
  select.innerHTML = `<option value="">전체 부서</option>${departments
    .map((department) => `<option value="${escapeAttr(department.name || "")}">${escapeHtml(department.name || "")}</option>`)
    .join("")}`;
  select.value = departments.some((department) => department.name === selected) ? selected : "";
}

function filterMembers(users) {
  const query = String(valueOf("memberSearchInput") || "").trim().toLowerCase();
  const department = valueOf("memberDepartmentFilter");
  return users.filter((user) => {
    const matchesQuery = !query || [user.id, user.name].some((value) => String(value || "").toLowerCase().includes(query));
    const matchesDepartment = !department || user.department === department;
    return matchesQuery && matchesDepartment;
  });
}

function memberExcelRow(user) {
  return [
    excelCell(user.id),
    excelCell(user.name),
    excelCell(user.department),
    excelCell(user.position),
    excelCell(roleLabel(user.role)),
    excelCell(employmentStatusLabel(user.approvalStatus)),
    excelCell(user.hireDate),
    excelCell(user.resignDate),
  ].join("");
}

function downloadMembersExcel() {
  if (!isAdmin()) return;
  const users = typeof projectRepository?.getUsers === "function" ? projectRepository.getUsers() : [];
  const rows = filterMembers(users);
  if (!rows.length) {
    alert("다운로드할 회원 목록이 없습니다.");
    return;
  }
  const headers = ["아이디", "이름", "부서", "직급", "권한", "재직여부", "입사일", "퇴사일"];
  const headerRow = `<Row>${headers.map((header) => excelCell(header)).join("")}</Row>`;
  const dataRows = rows.map((user) => `<Row>${memberExcelRow(user)}</Row>`).join("");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:html="http://www.w3.org/TR/REC-html40">
 <Worksheet ss:Name="회원 목록">
  <Table>
   ${headerRow}
   ${dataRows}
  </Table>
 </Worksheet>
</Workbook>`;
  const blob = new Blob([`\uFEFF${xml}`], { type: "application/vnd.ms-excel;charset=utf-8;" });
  triggerDownload(blob, `회원_목록_${downloadStamp()}.xls`);
}

function renderDepartments() {
  if (!isAdmin()) return;
  const departments = projectRepository.getDepartments?.() || [];
  const rows = $("departmentRows");
  if (!rows) return;
  rows.innerHTML =
    departments
      .map((department) => `<tr class="department-row" data-department-members="${escapeAttr(department.name || "")}">
      <td><button class="department-link-btn" type="button">${escapeHtml(department.name || "-")}</button></td>
      <td><input class="department-color-input" data-department-color="${escapeAttr(department.id)}" type="color" value="${escapeAttr(normalizeColorValue(department.color))}" aria-label="${escapeAttr(department.name || "부서")} 색상" /></td>
      <td>${Number(department.userCount || 0).toLocaleString("ko-KR")}</td>
      <td>${escapeHtml(department.createdAt || "-")}</td>
      <td>
        <button class="ghost-btn" data-department-edit="${escapeAttr(department.id)}" type="button">수정</button>
        <button class="ghost-btn danger" data-department-delete="${escapeAttr(department.id)}" type="button">삭제</button>
      </td>
    </tr>`)
      .join("") || '<tr><td colspan="5" class="empty-cell">등록된 부서가 없습니다.</td></tr>';
  rows.onclick = (event) => {
    const row = event.target.closest("[data-department-members]");
    if (!row || !rows.contains(row)) return;
    if (event.target.closest("[data-department-color], [data-department-edit], [data-department-delete]")) return;
    openMembersByDepartment(row.dataset.departmentMembers);
  };
  rows.querySelectorAll("[data-department-color]").forEach((input) => {
    input.addEventListener("change", () => changeDepartmentColor(input.dataset.departmentColor, input.value));
  });
  rows.querySelectorAll("[data-department-edit]").forEach((button) => {
    button.addEventListener("click", () => editDepartment(button.dataset.departmentEdit));
  });
  rows.querySelectorAll("[data-department-delete]").forEach((button) => {
    button.addEventListener("click", () => removeDepartment(button.dataset.departmentDelete));
  });
}

function openMembersByDepartment(departmentName) {
  if (!isAdmin()) return;
  const department = String(departmentName || "");
  switchView("members");
  renderMemberDepartmentFilter();
  setValue("memberDepartmentFilter", department);
  setValue("memberSearchInput", "");
  renderBasicManagement();
}

async function refreshDepartments() {
  if (!isAdmin()) return;
  try {
    await projectRepository.refreshDepartments();
    renderDepartments();
    renderBasicManagement();
  } catch (error) {
    console.error(error);
  }
}

async function addDepartment() {
  if (!isAdmin()) return;
  const name = prompt("추가할 부서명을 입력해 주세요.");
  if (!name || !name.trim()) return;
  try {
    await projectRepository.createDepartment(name.trim(), "#d9eadf");
    renderDepartments();
  } catch (error) {
    console.error(error);
    alert("부서 추가 중 오류가 발생했습니다.");
  }
}

async function editDepartment(id) {
  if (!isAdmin()) return;
  const department = (projectRepository.getDepartments?.() || []).find((item) => String(item.id) === String(id));
  if (!department) return;
  const name = prompt("수정할 부서명을 입력해 주세요.", department.name || "");
  if (!name || !name.trim() || name.trim() === department.name) return;
  try {
    await projectRepository.updateDepartment(id, name.trim(), normalizeColorValue(department.color));
    renderDepartments();
    renderBasicManagement();
  } catch (error) {
    console.error(error);
    alert(error.message || "부서 수정 중 오류가 발생했습니다.");
  }
}

async function changeDepartmentColor(id, color) {
  if (!isAdmin()) return;
  const department = (projectRepository.getDepartments?.() || []).find((item) => String(item.id) === String(id));
  if (!department) return;
  try {
    await projectRepository.updateDepartment(id, department.name, normalizeColorValue(color, department.color || "#d9eadf"));
    renderDepartments();
    renderVacationSchedule();
  } catch (error) {
    console.error(error);
    alert(error.message || "부서 색상 저장 중 오류가 발생했습니다.");
    renderDepartments();
  }
}

async function removeDepartment(id) {
  if (!isAdmin()) return;
  const department = (projectRepository.getDepartments?.() || []).find((item) => String(item.id) === String(id));
  if (!department) return;
  if (Number(department.userCount || 0) > 0) {
    alert("회원이 배정된 부서는 삭제할 수 없습니다. 먼저 회원의 부서를 변경해 주세요.");
    return;
  }
  if (!confirm(`'${department.name}' 부서를 삭제할까요?`)) return;
  try {
    await projectRepository.deleteDepartment(id);
    renderDepartments();
  } catch (error) {
    console.error(error);
    alert(error.message || "부서 삭제 중 오류가 발생했습니다.");
  }
}


function leaveStatusClass(status) {
  if (status === "승인") return "approved";
  if (status === "반려") return "rejected";
  return "pending";
}

function isCurrentMonthText(value) {
  const text = String(value || "").slice(0, 7);
  const now = new Date();
  const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  return text === currentMonth;
}

function formatLeaveDays(days) {
  const value = Number(days) || 0;
  return `${value.toLocaleString("ko-KR", { maximumFractionDigits: 1 })}일`;
}

function formatLeaveDateRange(request) {
  const start = request?.startDate || "";
  const end = request?.endDate || "";
  if (!start && !end) return "-";
  if (!end || start === end) return start;
  return `${start} ~ ${end}`;
}

function renderLeaveManagement() {
  if (!currentUser) return;
  const summary = projectRepository.getLeaveSummary();
  const requests = projectRepository.getLeaveRequests();
  setText("leaveTotalDays", formatLeaveDays(summary.totalDays));
  setText("leaveUsedDays", formatLeaveDays(summary.usedDays));
  setText("leaveRemainingDays", formatLeaveDays(summary.remainingDays));

  const rows = $("leaveRequestRows");
  if (!rows) return;
  rows.innerHTML =
    requests
      .map((request) => {
        const status = request.status || "대기";
        return `<tr>
      <td>${escapeHtml(formatLeaveDateRange(request))}</td>
      <td>${escapeHtml(request.type || "-")}</td>
      <td>${escapeHtml(formatLeaveDays(request.days))}</td>
      <td>${escapeHtml(request.reason || "-")}</td>
      <td><span class="status-badge ${leaveStatusClass(status)}">${escapeHtml(status)}</span></td>
      <td>${escapeHtml(request.createdAt || "-")}</td>
    </tr>`;
      })
      .join("") || '<tr><td colspan="6" class="empty-cell">등록된 연차 내역이 없습니다.</td></tr>';
}

function renderLeaveApprovals() {
  if (!isAdmin()) return;
  const requests = projectRepository.getLeaveApprovals();
  const pending = requests.filter((request) => request.status === "대기");
  const approved = requests.filter((request) => request.status === "승인");
  const approvedThisMonth = approved.filter((request) => isCurrentMonthText(request.approvedAt || request.updatedAt));
  const rejected = requests.filter((request) => request.status === "반려");
  setText("leavePendingCount", pending.length.toLocaleString("ko-KR"));
  setText("leaveApprovedCount", approvedThisMonth.length.toLocaleString("ko-KR"));
  setText("leaveRejectedCount", rejected.length.toLocaleString("ko-KR"));

  const rows = $("leaveApprovalRows");
  if (!rows) return;
  rows.innerHTML =
    requests
      .map((request) => {
        const status = request.status || "대기";
        const isPending = status === "대기";
        return `<tr>
      <td>${escapeHtml(request.userName || request.userId || "-")}</td>
      <td>${escapeHtml(formatLeaveDateRange(request))}</td>
      <td>${escapeHtml(request.type || "-")}</td>
      <td>${escapeHtml(formatLeaveDays(request.days))}</td>
      <td>${escapeHtml(request.reason || "-")}</td>
      <td><span class="status-badge ${leaveStatusClass(status)}">${escapeHtml(status)}</span></td>
      <td>
        ${
          isPending
            ? `<button class="ghost-btn" data-leave-approve="${escapeAttr(request.id)}" type="button">승인</button>
               <button class="ghost-btn danger" data-leave-reject="${escapeAttr(request.id)}" type="button">반려</button>`
            : escapeHtml(request.approvedBy || "-")
        }
      </td>
    </tr>`;
      })
      .join("") || '<tr><td colspan="7" class="empty-cell">승인할 연차 내역이 없습니다.</td></tr>';

  rows.querySelectorAll("[data-leave-approve]").forEach((button) => {
    button.addEventListener("click", () => updateLeaveApproval(button.dataset.leaveApprove, "approved"));
  });
  rows.querySelectorAll("[data-leave-reject]").forEach((button) => {
    button.addEventListener("click", () => updateLeaveApproval(button.dataset.leaveReject, "rejected"));
  });
}

async function refreshLeaves() {
  if (!currentUser) return;
  try {
    await projectRepository.refreshLeaves();
    renderLeaveManagement();
  } catch (error) {
    console.error(error);
  }
}

async function refreshLeaveApprovals() {
  if (!isAdmin()) return;
  try {
    await projectRepository.refreshLeaveApprovals();
    renderLeaveApprovals();
  } catch (error) {
    console.error(error);
  }
}

function leaveActiveUsers() {
  return projectRepository
    .getUsers()
    .filter((user) => user.approvalStatus === "활성화")
    .sort((a, b) => String(a.name || a.id || "").localeCompare(String(b.name || b.id || ""), "ko"));
}

function selectedLeaveUser() {
  return leaveActiveUsers().find((user) => user.id === selectedLeaveUserId) || null;
}

function renderLeaveUserResults() {
  const box = $("leaveUserResults");
  if (!box) return;
  const query = String(valueOf("leaveUserSearch") || "").trim().toLowerCase();
  if (!query) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }
  const rows = leaveActiveUsers()
    .filter((user) => [user.id, user.name, user.department].join(" ").toLowerCase().includes(query))
    .slice(0, 10);
  box.hidden = false;
  if (!rows.length) {
    box.innerHTML = '<div class="schedule-project-result is-empty" role="presentation">검색 결과가 없습니다.</div>';
    return;
  }
  box.innerHTML = rows
    .map(
      (user) => `<button type="button" class="schedule-project-result" data-leave-user-id="${escapeAttr(user.id)}">
        <span class="schedule-project-result-no">${escapeHtml(user.department || "-")}</span>
        <span class="schedule-project-result-name">${escapeHtml(user.name || user.id)} (${escapeHtml(user.id)})</span>
      </button>`
    )
    .join("");
  box.querySelectorAll("[data-leave-user-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const user = leaveActiveUsers().find((item) => item.id === button.dataset.leaveUserId);
      if (!user) return;
      selectedLeaveUserId = user.id;
      setValue("leaveUserId", user.id);
      setValue("leaveUserSearch", `${user.name || user.id} (${user.id})`);
      box.hidden = true;
      box.innerHTML = "";
    });
  });
}

async function openLeaveDialog() {
  if (!currentUser) return;
  const today = new Date().toISOString().slice(0, 10);
  const leaveUserField = $("leaveUserField");
  leaveUserField?.classList.toggle("hidden", !isAdmin());
  if (isAdmin()) {
    try {
      if (!projectRepository.getUsers().length) await projectRepository.refreshUsers();
    } catch (error) {
      console.error(error);
    }
  }
  selectedLeaveUserId = "";
  setValue("leaveUserSearch", "");
  setValue("leaveUserId", "");
  if ($("leaveUserResults")) {
    $("leaveUserResults").hidden = true;
    $("leaveUserResults").innerHTML = "";
  }
  setValue("leaveStartDate", today);
  setValue("leaveEndDate", today);
  setValue("leaveType", "연차");
  setValue("leaveDays", "1");
  setValue("leaveReason", "");
  setText("leaveMessage", "");
  $("leaveDialog")?.showModal();
}

function closeLeaveDialog() {
  selectedLeaveUserId = "";
  $("leaveUserResults") && ($("leaveUserResults").hidden = true);
  $("leaveDialog")?.close();
}

function updateLeaveDaysFromDates() {
  const type = valueOf("leaveType");
  if (type.includes("반차")) {
    setValue("leaveDays", "0.5");
    setValue("leaveEndDate", valueOf("leaveStartDate"));
    return;
  }
  const start = new Date(valueOf("leaveStartDate"));
  const end = new Date(valueOf("leaveEndDate"));
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end < start) {
    setValue("leaveDays", "1");
    return;
  }
  const diff = Math.floor((end - start) / (24 * 60 * 60 * 1000)) + 1;
  setValue("leaveDays", String(Math.max(1, diff)));
}

async function submitLeaveForm(event) {
  event.preventDefault();
  if (!currentUser) return;
  const payload = {
    startDate: valueOf("leaveStartDate"),
    endDate: valueOf("leaveEndDate") || valueOf("leaveStartDate"),
    type: valueOf("leaveType"),
    days: Number(valueOf("leaveDays")),
    reason: valueOf("leaveReason").trim(),
  };
  if (isAdmin()) {
    payload.userId = valueOf("leaveUserId") || selectedLeaveUserId;
    if (!payload.userId || !selectedLeaveUser()) {
      setText("leaveMessage", "회원을 검색해서 선택해 주세요.");
      return;
    }
  }
  if (!payload.startDate || !payload.endDate || !payload.days) {
    setText("leaveMessage", "연차 정보를 입력해 주세요.");
    return;
  }
  try {
    const result = await projectRepository.createLeaveRequest(payload);
    setText("leaveMessage", result.ok ? "연차가 등록되었습니다. 관리자 승인 후 차감됩니다." : result.message);
    if (!result.ok) return;
    closeLeaveDialog();
    renderLeaveManagement();
    if (isAdmin()) void refreshLeaveApprovals();
  } catch (error) {
    console.error(error);
    setText("leaveMessage", "연차 등록 중 오류가 발생했습니다.");
  }
}

async function updateLeaveApproval(id, status) {
  if (!isAdmin()) return;
  try {
    await projectRepository.approveLeaveRequest(id, status);
    renderLeaveApprovals();
    if (currentView === "leaveManagement") await refreshLeaves();
    if (currentView === "vacationSchedule") await refreshVacationSchedule();
  } catch (error) {
    console.error(error);
    alert("연차 승인 처리 중 오류가 발생했습니다.");
  }
}


function vacationSearchQuery() {
  return String(valueOf("vacationSearchInput") || "").trim().toLowerCase();
}

function datesBetween(startDate, endDate) {
  const dates = [];
  const start = parseDateParts(startDate);
  const end = parseDateParts(endDate || startDate);
  if (!start || !end) return dates;
  const cursor = new Date(start.year, start.month - 1, start.day);
  const last = new Date(end.year, end.month - 1, end.day);
  while (cursor <= last) {
    dates.push(dateFromParts(cursor.getFullYear(), cursor.getMonth() + 1, cursor.getDate()));
    cursor.setDate(cursor.getDate() + 1);
  }
  return dates;
}

function filteredVacationRequests() {
  const query = vacationSearchQuery();
  return projectRepository.getVacationSchedule().filter((request) => {
    const approved = request.status === "승인" || request.statusCode === "approved";
    if (!approved) return false;
    if (!query) return true;
    return [request.department, request.userName, request.userId, request.type, request.reason]
      .join(" ")
      .toLowerCase()
      .includes(query);
  });
}

function vacationRequestsForRange(start, end) {
  return filteredVacationRequests().filter((request) => {
    const requestStart = request.startDate || "";
    const requestEnd = request.endDate || requestStart;
    return requestStart <= end && requestEnd >= start;
  });
}

function vacationRequestsForMonth(year, month) {
  const monthStart = dateFromParts(year, month, 1);
  const monthEnd = dateFromParts(year, month, new Date(year, month, 0).getDate());
  return vacationRequestsForRange(monthStart, monthEnd);
}

function vacationEventLabel(request) {
  const department = request.department ? `${request.department} · ` : "";
  return `${department}${request.userName || request.userId || "-"} · ${request.type || "휴가"}`;
}

function vacationHolidaysForRange(start, end) {
  const company = projectRepository.getCompanyHolidays?.() || [];
  return [
    ...KOREA_PUBLIC_HOLIDAYS.map((holiday) => ({ ...holiday, kind: "공휴일" })),
    ...company.map((holiday) => ({ ...holiday, kind: holiday.kind || "회사휴일" })),
  ].filter((holiday) => {
    const date = String(holiday.date || "");
    return date >= start && date <= end;
  });
}

function vacationHolidaysForMonth(year, month) {
  const monthStart = dateFromParts(year, month, 1);
  const monthEnd = dateFromParts(year, month, new Date(year, month, 0).getDate());
  return vacationHolidaysForRange(monthStart, monthEnd);
}

function calendarCellDate(year, month, offset) {
  const date = new Date(year, month - 1, 1 + offset);
  return {
    year: date.getFullYear(),
    month: date.getMonth() + 1,
    day: date.getDate(),
    date: dateFromParts(date.getFullYear(), date.getMonth() + 1, date.getDate()),
  };
}

function vacationHolidayLabel(holiday) {
  return `${holiday.kind || "휴일"} · ${holiday.title || "-"}`;
}

function companyHolidayEventAttributes(holiday) {
  if (!holiday?.id) return "";
  return ` role="button" tabindex="0" data-company-holiday-id="${escapeHtml(holiday.id)}"`;
}

function vacationCalendarMode() {
  return $("vacationCalendarWeek")?.checked ? "week" : "month";
}

function renderVacationCalendarGrid() {
  const grid = $("vacationCalendarGrid");
  if (!grid) return;
  const mode = vacationCalendarMode();
  const { year, month } = vacationCursor;
  const today = todayDate();
  const weekday = ["일", "월", "화", "수", "목", "금", "토"];
  const cells = weekday.map((day) => `<div class="schedule-weekday">${day}</div>`);
  let start;
  let end;
  let totalCells;
  let getCell;
  let activeYear = year;
  let activeMonth = month;
  if (mode === "week") {
    start = startOfWeekMonday(vacationWeekAnchor);
    end = addDays(start, 6);
    const parts = parseDateParts(vacationWeekAnchor);
    if (parts) {
      activeYear = parts.year;
      activeMonth = parts.month;
    }
    setText("vacationMonthLabel", `${start} ~ ${end}`);
    totalCells = 7;
    getCell = (index) => {
      const date = addDays(start, index);
      const parts = parseDateParts(date);
      return { ...parts, date };
    };
  } else {
    const first = new Date(year, month - 1, 1);
    const startOffset = first.getDay();
    const firstCell = calendarCellDate(year, month, -startOffset);
    const lastCell = calendarCellDate(year, month, 34 - startOffset);
    start = firstCell.date;
    end = lastCell.date;
    setText("vacationMonthLabel", monthLabel(year, month));
    totalCells = 35;
    getCell = (index) => calendarCellDate(year, month, index - startOffset);
  }
  const requests = vacationRequestsForRange(start, end);
  const holidays = vacationHolidaysForRange(start, end);
  for (let i = 0; i < totalCells; i += 1) {
    const cell = getCell(i);
    const inMonth = cell.year === activeYear && cell.month === activeMonth;
    const date = cell.date;
    const dayRequests = requests.filter((request) => datesBetween(request.startDate, request.endDate).includes(date));
    const dayHolidays = holidays.filter((holiday) => holiday.date === date);
    cells.push(`<div class="schedule-day ${inMonth ? "" : "is-outside"} ${date === today ? "is-today" : ""}">
      <span>${cell.day}</span>
      ${dayHolidays.map((holiday) => `<div class="schedule-event is-holiday"${companyHolidayEventAttributes(holiday)}>
        <strong class="schedule-event-name">${escapeHtml(vacationHolidayLabel(holiday))}</strong>
      </div>`).join("")}
      ${dayRequests.map((request) => `<div class="schedule-event"${departmentEventStyle(request.department)}>
        <strong class="schedule-event-name">${escapeHtml(vacationEventLabel(request))}</strong>
      </div>`).join("")}
    </div>`);
  }
  grid.innerHTML = cells.join("");
}

function vacationListMode() {
  return $("vacationListWeek")?.checked ? "week" : "month";
}

function renderVacationScheduleRows() {
  const tbody = $("vacationScheduleRows");
  if (!tbody) return;
  const mode = vacationListMode();
  let start;
  let end;
  if (mode === "week") {
    start = startOfWeekMonday(vacationWeekAnchor);
    end = addDays(start, 6);
    setText("vacationListPeriodLabel", `${start} ~ ${end}`);
  } else {
    start = dateFromParts(vacationCursor.year, vacationCursor.month, 1);
    end = dateFromParts(vacationCursor.year, vacationCursor.month, new Date(vacationCursor.year, vacationCursor.month, 0).getDate());
    setText("vacationListPeriodLabel", monthLabel(vacationCursor.year, vacationCursor.month));
  }
  const leaveRows = vacationRequestsForRange(start, end).sort(
    (a, b) => String(a.startDate || "").localeCompare(String(b.startDate || "")) || String(a.userName || "").localeCompare(String(b.userName || ""), "ko")
  );
  const holidayRows = vacationHolidaysForRange(start, end).map((holiday) => ({
    id: holiday.id,
    isCompanyHoliday: Boolean(holiday.id),
    startDate: holiday.date,
    endDate: holiday.date,
    department: holiday.kind,
    userName: holiday.title,
    type: "휴일",
    status: holiday.kind,
  }));
  const rows = [...leaveRows, ...holidayRows].sort((a, b) => String(a.startDate || "").localeCompare(String(b.startDate || "")));
  tbody.innerHTML = rows.length
    ? rows
        .map((request) => {
          const rowAttrs = request.isCompanyHoliday
            ? ` data-company-holiday-id="${escapeHtml(request.id)}"`
            : ` style="background:${escapeAttr(departmentColor(request.department))}"`;
          return `<tr${rowAttrs}>
        <td>${escapeHtml(formatLeaveDateRange(request))}</td>
        <td>${escapeHtml(request.department || "-")}</td>
        <td>${escapeHtml(request.userName || request.userId || "-")}</td>
        <td>${escapeHtml(request.type || "-")}</td>
      </tr>`;
        })
        .join("")
    : '<tr><td colspan="4" class="empty-cell">등록된 휴가 일정이 없습니다.</td></tr>';
}

function renderVacationSchedule() {
  if (!$("vacationScheduleView")) return;
  ["companyHolidayAddBtn", "companyHolidayAddBtnList", "vacationLeaveAddBtn", "vacationLeaveAddBtnList"].forEach((id) => {
    $(id)?.classList.toggle("hidden", !isAdmin());
  });
  renderVacationCalendarGrid();
  renderVacationScheduleRows();
}

async function refreshVacationSchedule() {
  try {
    if (currentUser) {
      await projectRepository.refreshVacationSchedule();
    } else {
      projectRepository.vacationScheduleCache = [];
      projectRepository.companyHolidaysCache = [];
    }
    renderVacationSchedule();
  } catch (error) {
    console.error(error);
  }
}

function moveVacationMonth(amount) {
  if (vacationCalendarMode() === "week") {
    vacationWeekAnchor = addDays(vacationWeekAnchor, amount * 7);
    renderVacationSchedule();
    return;
  }
  const date = new Date(vacationCursor.year, vacationCursor.month - 1 + amount, 1);
  vacationCursor = { year: date.getFullYear(), month: date.getMonth() + 1 };
  renderVacationSchedule();
}

function moveVacationList(amount) {
  if (vacationListMode() === "week") {
    vacationWeekAnchor = addDays(vacationWeekAnchor, amount * 7);
  } else {
    moveVacationMonth(amount);
    return;
  }
  renderVacationSchedule();
}

function vacationLeaveActiveUsers() {
  return projectRepository
    .getUsers()
    .filter((user) => user.approvalStatus === "활성화")
    .sort((a, b) => String(a.name || a.id || "").localeCompare(String(b.name || b.id || ""), "ko"));
}

function selectedVacationLeaveUser() {
  return vacationLeaveActiveUsers().find((user) => user.id === selectedVacationLeaveUserId) || null;
}

function renderVacationLeaveUserResults() {
  const box = $("vacationLeaveUserResults");
  if (!box) return;
  const query = String(valueOf("vacationLeaveUserSearch") || "").trim().toLowerCase();
  if (!query) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }
  const rows = vacationLeaveActiveUsers()
    .filter((user) => [user.id, user.name, user.department].join(" ").toLowerCase().includes(query))
    .slice(0, 10);
  box.hidden = false;
  if (!rows.length) {
    box.innerHTML = '<div class="schedule-project-result is-empty" role="presentation">검색 결과가 없습니다.</div>';
    return;
  }
  box.innerHTML = rows
    .map(
      (user) => `<button type="button" class="schedule-project-result" data-vacation-leave-user-id="${escapeAttr(user.id)}">
        <span class="schedule-project-result-no">${escapeHtml(user.department || "-")}</span>
        <span class="schedule-project-result-name">${escapeHtml(user.name || user.id)} (${escapeHtml(user.id)})</span>
      </button>`
    )
    .join("");
  box.querySelectorAll("[data-vacation-leave-user-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const user = vacationLeaveActiveUsers().find((item) => item.id === button.dataset.vacationLeaveUserId);
      if (!user) return;
      selectedVacationLeaveUserId = user.id;
      setValue("vacationLeaveUserId", user.id);
      setValue("vacationLeaveUserSearch", `${user.name || user.id} (${user.id})`);
      box.hidden = true;
      box.innerHTML = "";
    });
  });
}

async function openVacationLeaveDialog() {
  if (!isAdmin()) return;
  try {
    if (!projectRepository.getUsers().length) await projectRepository.refreshUsers();
  } catch (error) {
    console.error(error);
  }
  const today = todayDate();
  selectedVacationLeaveUserId = "";
  setValue("vacationLeaveUserSearch", "");
  setValue("vacationLeaveUserId", "");
  setValue("vacationLeaveStartDate", today);
  setValue("vacationLeaveEndDate", today);
  setValue("vacationLeaveType", "연차");
  setValue("vacationLeaveDays", "1");
  setValue("vacationLeaveMemo", "");
  setText("vacationLeaveMessage", "");
  if ($("vacationLeaveUserResults")) {
    $("vacationLeaveUserResults").hidden = true;
    $("vacationLeaveUserResults").innerHTML = "";
  }
  $("vacationLeaveDialog")?.showModal();
}

function closeVacationLeaveDialog() {
  selectedVacationLeaveUserId = "";
  $("vacationLeaveUserResults") && ($("vacationLeaveUserResults").hidden = true);
  $("vacationLeaveDialog")?.close();
}

function updateVacationLeaveDaysFromDates() {
  const type = valueOf("vacationLeaveType");
  if (type.includes("반차")) {
    setValue("vacationLeaveDays", "0.5");
    setValue("vacationLeaveEndDate", valueOf("vacationLeaveStartDate"));
    return;
  }
  const start = new Date(valueOf("vacationLeaveStartDate"));
  const end = new Date(valueOf("vacationLeaveEndDate"));
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end < start) {
    setValue("vacationLeaveDays", "1");
    return;
  }
  const diff = Math.floor((end - start) / (24 * 60 * 60 * 1000)) + 1;
  setValue("vacationLeaveDays", String(Math.max(1, diff)));
}

async function submitVacationLeaveForm(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const userId = valueOf("vacationLeaveUserId") || selectedVacationLeaveUserId;
  const startDate = valueOf("vacationLeaveStartDate");
  const endDate = valueOf("vacationLeaveEndDate") || startDate;
  const type = valueOf("vacationLeaveType") || "연차";
  const days = Number(valueOf("vacationLeaveDays"));
  const user = selectedVacationLeaveUser();
  if (!userId || !startDate || !endDate || !type || !days || !user) {
    setText("vacationLeaveMessage", "회원, 시작일, 종료일, 구분을 선택해 주세요.");
    return;
  }
  const payload = {
    userId,
    startDate,
    endDate,
    type,
    days,
    reason: valueOf("vacationLeaveMemo").trim(),
    autoApprove: true,
  };
  try {
    await projectRepository.createLeaveRequest(payload);
    closeVacationLeaveDialog();
    await projectRepository.refreshVacationSchedule();
    await projectRepository.refreshUsers();
    if (currentView === "leaveApprovals") await refreshLeaveApprovals();
    if (currentView === "leaveManagement") await refreshLeaves();
    renderVacationSchedule();
    renderBasicManagement();
  } catch (error) {
    console.error(error);
    setText("vacationLeaveMessage", error.message || "연차 등록 중 오류가 발생했습니다.");
  }
}

function findCompanyHoliday(id) {
  return (projectRepository.getCompanyHolidays?.() || []).find((holiday) => String(holiday.id) === String(id));
}

function openCompanyHolidayDialog(holidayId = "") {
  if (!isAdmin()) return;
  const holiday = holidayId ? findCompanyHoliday(holidayId) : null;
  editingCompanyHolidayId = holiday ? String(holiday.id) : "";
  setText("companyHolidayDialogTitle", holiday ? "휴일 수정" : "휴일 추가");
  setValue("companyHolidayDialogDate", holiday?.date || todayDate());
  setValue("companyHolidayDialogKind", holiday?.kind || "회사휴일");
  setValue("companyHolidayDialogName", holiday?.title || "");
  setText("companyHolidayDialogMessage", "");
  $("companyHolidayDeleteBtn")?.classList.toggle("hidden", !holiday);
  $("companyHolidayDialog")?.showModal();
}

function closeCompanyHolidayDialog() {
  editingCompanyHolidayId = "";
  $("companyHolidayDeleteBtn")?.classList.add("hidden");
  $("companyHolidayDialog")?.close();
}

async function saveCompanyHoliday(event) {
  event?.preventDefault();
  if (!isAdmin()) return;
  const payload = {
    date: valueOf("companyHolidayDialogDate"),
    kind: valueOf("companyHolidayDialogKind") || "회사휴일",
    title: valueOf("companyHolidayDialogName").trim(),
  };
  if (!payload.date || !payload.title) {
    setText("companyHolidayDialogMessage", "휴일 일자와 이름을 입력해 주세요.");
    return;
  }
  try {
    if (editingCompanyHolidayId) {
      await projectRepository.updateCompanyHoliday(editingCompanyHolidayId, payload);
    } else {
      await projectRepository.createCompanyHoliday(payload);
    }
    closeCompanyHolidayDialog();
    renderVacationSchedule();
  } catch (error) {
    console.error(error);
    setText("companyHolidayDialogMessage", error.message || "휴일 저장 중 오류가 발생했습니다.");
  }
}

async function deleteCompanyHoliday() {
  if (!isAdmin() || !editingCompanyHolidayId) return;
  if (!confirm("등록한 휴일을 삭제할까요?")) return;
  try {
    await projectRepository.deleteCompanyHoliday(editingCompanyHolidayId);
    closeCompanyHolidayDialog();
    renderVacationSchedule();
  } catch (error) {
    console.error(error);
    setText("companyHolidayDialogMessage", error.message || "휴일 삭제 중 오류가 발생했습니다.");
  }
}


function issueProjects() {
  return monthlyIssueProjectSource().filter(
    (project) =>
      project.hasIssue ||
      (project.issues || []).some((issue) => {
        const normalized = normalizeIssue(issue);
        return !normalized.resolved && String(normalized.memo || "").trim();
      })
  );
}

function latestIssueText(project) {
  const issue = latestProjectIssue(project);
  if (!issue) return project.hasIssue ? "이슈 체크됨" : "-";
  return String(issue.memo || "").trim().replace(/\s+/g, " ") || "내용 없음";
}

function renderIssueProjectSummary(rows = issueProjects()) {
  const progress = rows.filter((project) => !isInactiveProgressMilestone(projectMilestone(project)));
  const review = rows.filter((project) => ["고객검수중", "내용증명", "법정다툼", "작업중단-고객요청"].includes(projectMilestone(project)));
  const pmCount = new Set(rows.map((project) => String(project.pm || "").trim()).filter(Boolean)).size;
  setText("issueProjectsTitle", `이슈 프로젝트(${rows.length.toLocaleString("ko-KR")}건)`);
  setText("issueProjectTotal", rows.length.toLocaleString("ko-KR"));
  setText("issueProgressCount", progress.length.toLocaleString("ko-KR"));
  setText("issueReviewCount", review.length.toLocaleString("ko-KR"));
  setText("issuePmCount", pmCount.toLocaleString("ko-KR"));
}

function renderIssueProjectRows() {
  const rows = sortedProjectRows(issueProjects(), "issues");
  updateListSortUi();
  const tbody = $("issueProjectRows");
  if (!tbody) return;
  renderIssueProjectSummary(rows);
  tbody.innerHTML = rows.length
    ? rows
        .map((project) => {
          const selected = project.id === selectedId && document.body.classList.contains("detail-open");
          const latestIssue = latestProjectIssue(project);
          return `
            <tr data-issue-project-id="${escapeAttr(project.id)}" class="${selected ? "selected" : ""}">
              <td>${escapeHtml(project.projectNo || "-")}</td>
              <td>
                <div class="project-title-cell">
                  ${buildDueDateBadge(project)}
                  <span class="project-name">${escapeHtml(project.name || "이름 없음")}</span>
                  ${buildProjectFlagIcons(project)}
                </div>
              </td>
              <td><span class="issue-status-badge">${escapeHtml(latestIssue?.status || "-")}</span></td>
              <td><span class="issue-type-badge">${escapeHtml(latestIssue?.type || "-")}</span></td>
              <td>${escapeHtml(project.pm || "-")}</td>
              <td class="issue-summary-cell">${escapeHtml(latestIssueText(project))}</td>
              <td>${buildHomeAndIntranetShortcutActions(project)}</td>
            </tr>
          `;
        })
        .join("")
    : '<tr><td colspan="7" class="empty-cell">이슈 체크된 프로젝트가 없습니다.</td></tr>';

  tbody.querySelectorAll("[data-issue-project-id]").forEach((row) => {
    row.addEventListener("click", (event) => {
      event.stopPropagation();
      closeListFilterMenus();
      cancelCreateProject();
      selectedId = row.dataset.issueProjectId;
      document.body.classList.remove("schedule-detail-open");
      document.body.classList.add("detail-open");
      closeDetailDropdowns();
      renderDetail();
      saveUiSessionState();
      tbody.querySelectorAll("tr[data-issue-project-id]").forEach((item) => {
        item.classList.toggle("selected", item.dataset.issueProjectId === selectedId);
      });
    });
  });
  attachShortcutButtonHandlers(tbody);
}


function allScheduleEntries() {
  const sourceProjects = projectScheduleVisibleProjects();
  const canSeeEveryEntry = canViewAllProjectSchedules();
  return sourceProjects.flatMap((project) =>
    (project.schedules || []).flatMap((entry) => {
      const normalized = normalizeScheduleEntry(project, entry);
      const enriched = {
        ...normalized,
        projectId: project.id,
        projectNo: normalized.projectNo || project.projectNo || "",
        projectName: normalized.projectName || project.name || "",
      };
      return canSeeEveryEntry || canViewProjectScheduleEntry(enriched) ? [enriched] : [];
    })
  );
}

function scheduleStaffForMilestone(project, milestone) {
  const value = String(milestone || projectMilestone(project) || "").trim();
  if (value === "메인시안중" || value === "서브시안중" || value === "상세디자인") {
    return { staffRole: "디자이너", staffName: project.designer || "" };
  }
  if (value === "퍼블리싱중") return { staffRole: "퍼블리셔", staffName: project.publisher || "" };
  if (value === "프로그램중") return { staffRole: "프로그래머", staffName: project.programmer || "" };
  return { staffRole: "PM", staffName: project.pm || "" };
}

function scheduleStaffForProject(project) {
  return scheduleStaffForMilestone(project, projectMilestone(project));
}

function scheduleStaffForCurrentUser(project = null) {
  if (!currentUser) return null;
  const name = assignedProjectUserName();
  if (!name) return null;
  if (isDepartment("pm")) return { staffRole: "PM", staffName: name };
  if (isDepartment("디자인", "디자이너") && (!project || isAssignedProject(project))) return { staffRole: "디자이너", staffName: name };
  if (isDepartment("퍼블리싱", "퍼블리셔") && (!project || isAssignedProject(project))) return { staffRole: "퍼블리셔", staffName: name };
  if (isDepartment("프로그램", "프로그래머") && (!project || isAssignedProject(project))) return { staffRole: "프로그래머", staffName: name };
  return null;
}

function defaultScheduleStaff(project) {
  return scheduleStaffForCurrentUser(project) || scheduleStaffForProject(project);
}

function scheduleStaffBadgeText(entry) {
  return entry.staffName || "-";
}

const DEMO_SCHEDULE_DETAILS = [
  "고객 자료 수령 확인",
  "디자인 시안 공유",
  "퍼블리싱 점검",
  "개발 QA 일정",
  "오픈 전 최종 확인",
  "내부 검토 미팅",
  "고객 피드백 회신",
  "마일스톤 점검",
];

function demoScheduleDetail(project, index) {
  const milestone = projectMilestone(project);
  if (milestone) return `${milestone} 샘플 일정`;
  return DEMO_SCHEDULE_DETAILS[index % DEMO_SCHEDULE_DETAILS.length];
}

function weekdayDatesInMonth(year, month) {
  const daysInMonth = new Date(year, month, 0).getDate();
  const dates = [];
  for (let day = 1; day <= daysInMonth; day += 1) {
    const weekday = new Date(year, month - 1, day).getDay();
    if (weekday === 0 || weekday === 6) continue;
    dates.push(dateFromParts(year, month, day));
  }
  return dates;
}

function getDemoScheduleEntries(year, month) {
  if (!isReadOnlyMode()) return [];
  const weekdayDates = weekdayDatesInMonth(year, month);
  if (!weekdayDates.length) return [];
  return accessibleProjects().map((project, index) => {
    const date = weekdayDates[index % weekdayDates.length];
    const staff = scheduleStaffForProject(project);
    return {
      id: `demo-schedule-${project.id}`,
      date,
      projectId: project.id,
      projectNo: project.projectNo || "",
      projectName: project.name || "",
      milestone: projectMilestone(project) || "",
      staffRole: staff.staffRole,
      staffName: staff.staffName,
      detail: demoScheduleDetail(project, index),
      completed: index % 7 === 6,
      isDemoSchedule: true,
    };
  });
}

function getDemoScheduleEntriesForRange(start, end) {
  if (!isReadOnlyMode() || !start || !end) return [];
  const startParts = parseDateParts(start);
  const endParts = parseDateParts(end);
  if (!startParts || !endParts) return [];
  const entries = [];
  let year = startParts.year;
  let month = startParts.month;
  const endKey = endParts.year * 100 + endParts.month;
  while (year * 100 + month <= endKey) {
    entries.push(...getDemoScheduleEntries(year, month));
    month += 1;
    if (month > 12) {
      month = 1;
      year += 1;
    }
  }
  return entries.filter((entry) => String(entry.date || "") >= start && String(entry.date || "") <= end);
}

function scheduleEntriesWithDemo(options = {}) {
  const { year, month, start, end } = options;
  const real = filteredScheduleEntries().filter((entry) => {
    const date = String(entry.date || "");
    if (start && end) return date >= start && date <= end;
    if (year && month) {
      const parts = parseDateParts(date);
      return parts && parts.year === year && parts.month === month;
    }
    return true;
  });
  if (!isReadOnlyMode()) return real;
  let demo = [];
  if (year && month) demo = getDemoScheduleEntries(year, month);
  else if (start && end) demo = getDemoScheduleEntriesForRange(start, end);
  else {
    const today = new Date();
    demo = getDemoScheduleEntries(today.getFullYear(), today.getMonth() + 1);
  }
  const merged = [...real, ...demo];
  if (start && end) {
    return merged.filter((entry) => String(entry.date || "") >= start && String(entry.date || "") <= end);
  }
  if (year && month) {
    return merged.filter((entry) => {
      const parts = parseDateParts(entry.date);
      return parts && parts.year === year && parts.month === month;
    });
  }
  return merged;
}

function dateFromParts(year, month, day) {
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function addDays(dateText, amount) {
  const parts = parseDateParts(dateText);
  const base = parts ? new Date(parts.year, parts.month - 1, parts.day) : new Date();
  base.setDate(base.getDate() + amount);
  return dateFromParts(base.getFullYear(), base.getMonth() + 1, base.getDate());
}

function startOfWeekMonday(dateText) {
  const parts = parseDateParts(dateText);
  const base = parts ? new Date(parts.year, parts.month - 1, parts.day) : new Date();
  const day = base.getDay() || 7;
  base.setDate(base.getDate() - day + 1);
  return dateFromParts(base.getFullYear(), base.getMonth() + 1, base.getDate());
}

function scheduleSearchQuery() {
  return String(valueOf("scheduleSearchInput") || "").trim().toLowerCase();
}

function filteredScheduleEntries() {
  const query = scheduleSearchQuery();
  return allScheduleEntries().filter((entry) => {
    if (!query) return true;
    return [entry.projectName, entry.projectNo].join(" ").toLowerCase().includes(query);
  });
}

function monthLabel(year, month) {
  return `${year}년 ${month}월`;
}

function scheduleCalendarMode() {
  return $("scheduleCalendarWeek")?.checked ? "week" : "month";
}

function scheduleListMode() {
  return $("scheduleListWeek")?.checked ? "week" : "month";
}

function focusScheduleCursorOnDate(dateText) {
  const parts = parseDateParts(dateText);
  if (!parts) return;
  scheduleCursor = { year: parts.year, month: parts.month };
  scheduleWeekAnchor = dateText;
}

function renderScheduleCalendarGrid() {
  const grid = $("scheduleCalendarGrid");
  if (!grid) return;
  const mode = scheduleCalendarMode();
  const { year, month } = scheduleCursor;
  const today = todayDate();
  const weekday = ["일", "월", "화", "수", "목", "금", "토"];
  const cells = weekday.map((day) => `<div class="schedule-weekday">${day}</div>`);
  let start;
  let end;
  let totalCells;
  let getCell;
  let activeYear = year;
  let activeMonth = month;
  if (mode === "week") {
    start = startOfWeekMonday(scheduleWeekAnchor);
    end = addDays(start, 6);
    const parts = parseDateParts(scheduleWeekAnchor);
    if (parts) {
      activeYear = parts.year;
      activeMonth = parts.month;
    }
    setText("scheduleMonthLabel", `${start} ~ ${end}`);
    totalCells = 7;
    getCell = (index) => {
      const date = addDays(start, index);
      const parts = parseDateParts(date);
      return { ...parts, date };
    };
  } else {
    const first = new Date(year, month - 1, 1);
    const startOffset = first.getDay();
    const firstCell = calendarCellDate(year, month, -startOffset);
    const lastCell = calendarCellDate(year, month, 34 - startOffset);
    start = firstCell.date;
    end = lastCell.date;
    setText("scheduleMonthLabel", monthLabel(year, month));
    totalCells = 35;
    getCell = (index) => calendarCellDate(year, month, index - startOffset);
  }
  const entries = scheduleEntriesWithDemo({ start, end });
  for (let i = 0; i < totalCells; i += 1) {
    const cell = getCell(i);
    const inMonth = cell.year === activeYear && cell.month === activeMonth;
    const date = cell.date;
    const visibleEntries = entries.filter((entry) => entry.date === date);
    cells.push(`<button class="schedule-day ${inMonth ? "" : "is-outside"} ${date === today ? "is-today" : ""}" type="button" data-schedule-date="${date}">
      <span>${cell.day}</span>
      ${visibleEntries.map((entry) => `<div class="schedule-event ${entry.completed ? "is-completed" : ""}" data-schedule-entry-id="${escapeAttr(entry.id)}">
        <strong class="schedule-event-name">${escapeHtml(entry.projectName || "-")}</strong>
        <small class="schedule-event-detail">${escapeHtml(entry.detail || "-")}</small>
      </div>`).join("")}
    </button>`);
  }
  grid.innerHTML = cells.join("");
  grid.querySelectorAll("[data-schedule-entry-id]").forEach((item) => {
    item.addEventListener("click", (event) => {
      event.stopPropagation();
      if (document.body.classList.contains("schedule-detail-open")) closeDetail();
      const entry = allScheduleEntries().find((row) => row.id === item.dataset.scheduleEntryId);
      const project = entry ? findProjectByScheduleInput(entry.projectId) : null;
      if (entry && canManageProjectScheduleEntry(project, entry)) openScheduleDialog(entry.date || todayDate(), { editingEntry: entry });
      else if (entry) showScheduleProjectDetail(entry);
    });
  });
  grid.querySelectorAll("[data-schedule-date]").forEach((item) => {
    item.addEventListener("click", () => {
      if (!currentUser || (!canManageAllProjectSchedules() && !canUseAssignedProjectSchedules())) return;
      openScheduleDialog(item.dataset.scheduleDate);
    });
  });
}

function renderScheduleListRows() {
  const tbody = $("scheduleRows");
  if (!tbody) return;
  const mode = scheduleListMode();
  let start;
  let end;
  if (mode === "week") {
    start = startOfWeekMonday(scheduleWeekAnchor);
    end = addDays(start, 6);
    setText("scheduleListPeriodLabel", `${start} ~ ${end}`);
  } else {
    start = dateFromParts(scheduleCursor.year, scheduleCursor.month, 1);
    end = dateFromParts(scheduleCursor.year, scheduleCursor.month, new Date(scheduleCursor.year, scheduleCursor.month, 0).getDate());
    setText("scheduleListPeriodLabel", monthLabel(scheduleCursor.year, scheduleCursor.month));
  }
  const rows = scheduleEntriesWithDemo({ start, end })
    .sort((a, b) => String(a.date || "").localeCompare(String(b.date || "")) || String(a.projectName || "").localeCompare(String(b.projectName || ""), "ko"));
  tbody.innerHTML = rows.length
    ? rows.map((entry) => {
        const project = findProjectByScheduleInput(entry.projectId);
        const canToggle = canManageProjectScheduleEntry(project, entry);
        return `<tr data-schedule-entry-id="${escapeAttr(entry.id)}" class="${entry.completed ? "is-schedule-completed" : ""}">
        <td>${escapeHtml(entry.date || "-")}</td>
        <td class="schedule-project-name-cell">${escapeHtml(entry.projectName || "-")}</td>
        <td><span class="schedule-milestone-badge">${escapeHtml(entry.milestone || "-")}</span></td>
        <td><span class="schedule-staff-badge">${escapeHtml(scheduleStaffBadgeText(entry))}</span></td>
        <td>${escapeHtml(entry.detail || "-")}</td>
        <td class="schedule-list-complete-cell">
          <label class="schedule-list-complete" title="완료">
            <input type="checkbox" class="schedule-list-complete-input" data-schedule-entry-id="${escapeAttr(entry.id)}" ${entry.completed ? "checked" : ""} ${canToggle ? "" : "disabled"} />
          </label>
        </td>
      </tr>`;
      }).join("")
    : '<tr><td colspan="6" class="empty-cell">등록된 일정이 없습니다.</td></tr>';
  tbody.querySelectorAll("[data-schedule-entry-id]").forEach((row) => {
    row.querySelector(".schedule-list-complete-input")?.addEventListener("change", (event) => {
      event.stopPropagation();
      const input = event.target;
      const checked = input.checked;
      if (!toggleScheduleCompleted(input.dataset.scheduleEntryId, checked)) {
        input.checked = !checked;
      }
    });
    row.addEventListener("click", (event) => {
      if (event.target.closest(".schedule-list-complete")) return;
      event.stopPropagation();
      if (document.body.classList.contains("schedule-detail-open")) closeDetail();
      const entry = allScheduleEntries().find((item) => item.id === row.dataset.scheduleEntryId);
      const project = entry ? findProjectByScheduleInput(entry.projectId) : null;
      if (entry && canManageProjectScheduleEntry(project, entry)) openScheduleDialog(entry.date || todayDate(), { editingEntry: entry });
      else if (entry) showScheduleProjectDetail(entry);
    });
  });
}

function renderScheduleViews() {
  if (!$("scheduleView")) return;
  bindScheduleUi();
  renderScheduleCalendarGrid();
  renderScheduleListRows();
}

function findProjectByScheduleInput(projectId) {
  const source = canManageAllProjectSchedules() ? projects : projects.filter(isAssignedProject);
  return source.find((project) => project.id === projectId) || null;
}

function selectedScheduleProject() {
  const id = valueOf("scheduleProjectId");
  return findProjectByScheduleInput(id);
}

function showScheduleProjectDetail(entry) {
  const project = accessibleProjects().find((item) => item.id === entry.projectId);
  if (!project) return;
  selectedId = project.id;
  isCreatingProject = false;
  draftProject = null;
  document.body.classList.add("detail-open", "schedule-detail-open");
  openDetailDropdowns();
  renderDetail();
  openProjectScheduleDropdown();
  saveUiSessionState();
}

function renderScheduleProjectResults() {
  const box = $("scheduleProjectResults");
  if (!box) return;
  const query = String(valueOf("scheduleProjectSearch") || "").trim().toLowerCase();
  if (!query) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }
  const source = canViewAllProjectSchedules() ? projects : accessibleProjects();
  const rows = source.filter((project) => [project.name, project.projectNo].join(" ").toLowerCase().includes(query)).slice(0, 10);
  box.hidden = false;
  if (!rows.length) {
    box.innerHTML = '<div class="schedule-project-result is-empty" role="presentation">검색 결과가 없습니다.</div>';
    return;
  }
  box.innerHTML = rows
    .map(
      (project) => `<button type="button" class="schedule-project-result" data-schedule-project-id="${escapeAttr(project.id)}" role="option">
        <span class="schedule-project-result-no">${escapeHtml(project.projectNo || "-")}</span>
        <span class="schedule-project-result-name">${escapeHtml(project.name || "-")}</span>
      </button>`
    )
    .join("");
  box.querySelectorAll("[data-schedule-project-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const project = findProjectByScheduleInput(button.dataset.scheduleProjectId);
      if (!project) return;
      setValue("scheduleProjectId", project.id);
      setValue("scheduleProjectSearch", `${project.projectNo || "-"} · ${project.name || "-"}`);
      const staff = defaultScheduleStaff(project);
      setValue("scheduleMilestoneSelect", projectMilestone(project) || "");
      setValue("scheduleStaffRoleSelect", staff.staffRole);
      setValue("scheduleStaffNameInput", staff.staffName);
      box.hidden = true;
      syncScheduleAssignFieldsVisibility();
    });
  });
}

function syncScheduleAssignFieldsVisibility() {
  $("scheduleAssignFields")?.classList.toggle("hidden", !usesFullScheduleDialog() || !valueOf("scheduleProjectId"));
}

function openScheduleDialog(date = todayDate(), options = {}) {
  const editingEntry = options.editingEntry || null;
  scheduleDialogEditId = editingEntry?.id || "";
  const presetProjectId = editingEntry?.projectId || options.projectId || "";
  const project = presetProjectId ? findProjectByScheduleInput(presetProjectId) : null;
  const canOpen = editingEntry
    ? canManageProjectScheduleEntry(project, editingEntry)
    : project
      ? canCreateProjectSchedule(project)
      : Boolean(currentUser && (canManageAllProjectSchedules() || canUseAssignedProjectSchedules()));
  if (!canOpen) {
    alert("현재 계정은 프로젝트 일정을 등록하거나 수정할 권한이 없습니다.");
    return;
  }
  setText("scheduleDialogTitle", editingEntry ? "일정 수정" : "일정 추가");
  setText("scheduleDialogDate", `${date} 일정을 ${editingEntry ? "수정" : "등록"}합니다.`);
  setValue("scheduleDateInput", editingEntry?.date || date);
  setValue("scheduleDetailInput", editingEntry?.detail || "");
  $("scheduleCompletedField")?.classList.toggle("hidden", !editingEntry);
  setChecked("scheduleCompletedInput", Boolean(editingEntry?.completed));
  if ($("scheduleMilestoneSelect")) {
    $("scheduleMilestoneSelect").innerHTML =
      `<option value=""></option>` +
      dashboardMilestones().map((item) => `<option value="${escapeAttr(item)}">${escapeHtml(item)}</option>`).join("");
  }
  if (project && editingEntry) {
    const staff = { staffRole: editingEntry.staffRole, staffName: editingEntry.staffName };
    setValue("scheduleProjectId", project.id);
    setValue("scheduleProjectSearch", `${project.projectNo || "-"} · ${project.name || "-"}`);
    setValue("scheduleMilestoneSelect", editingEntry.milestone || projectMilestone(project) || "");
    setValue("scheduleStaffRoleSelect", staff.staffRole || "PM");
    setValue("scheduleStaffNameInput", staff.staffName || "");
  } else if (project) {
    const staff = defaultScheduleStaff(project);
    setValue("scheduleProjectId", project.id);
    setValue("scheduleProjectSearch", `${project.projectNo || "-"} · ${project.name || "-"}`);
    setValue("scheduleMilestoneSelect", projectMilestone(project) || "");
    setValue("scheduleStaffRoleSelect", staff.staffRole);
    setValue("scheduleStaffNameInput", staff.staffName || "");
  } else {
    setValue("scheduleProjectId", "");
    setValue("scheduleProjectSearch", "");
    setValue("scheduleMilestoneSelect", "");
    setValue("scheduleStaffRoleSelect", "PM");
    setValue("scheduleStaffNameInput", "");
  }
  if ($("scheduleProjectResults")) {
    $("scheduleProjectResults").hidden = true;
    $("scheduleProjectResults").innerHTML = "";
  }
  $("scheduleProjectDetailButton")?.classList.toggle("hidden", !editingEntry);
  $("scheduleSubmitButton").textContent = editingEntry ? "일정 수정" : "일정 추가";
  syncScheduleAssignFieldsVisibility();
  $("scheduleDialog")?.showModal();
}

function closeScheduleDialog() {
  scheduleDialogEditId = "";
  $("scheduleProjectResults") && ($("scheduleProjectResults").hidden = true);
  $("scheduleDialog")?.close();
}

function saveScheduleEntryToProject(project, entry) {
  project.schedules = project.schedules || [];
  const index = project.schedules.findIndex((item) => item.id === entry.id);
  if (index >= 0) project.schedules[index] = entry;
  else project.schedules.unshift(entry);
}

function removeScheduleEntry(entryId) {
  projects.forEach((project) => {
    project.schedules = (project.schedules || []).filter((entry) => entry.id !== entryId);
  });
}

async function submitScheduleForm(event) {
  event.preventDefault();
  const project = selectedScheduleProject();
  if (!project) {
    alert("프로젝트를 선택해 주세요.");
    return;
  }
  const previousEntry = scheduleDialogEditId ? (project.schedules || []).find((entry) => entry.id === scheduleDialogEditId) : null;
  if (!canManageProjectScheduleEntry(project, previousEntry)) {
    alert("현재 계정은 이 일정을 등록하거나 수정할 권한이 없습니다.");
    return;
  }
  const detail = valueOf("scheduleDetailInput").trim();
  if (!detail) {
    alert("상세 내용을 입력해 주세요.");
    return;
  }
  const currentStaff = !scheduleDialogEditId ? scheduleStaffForCurrentUser(project) : null;
  const entry = {
    id: scheduleDialogEditId || crypto.randomUUID(),
    date: valueOf("scheduleDateInput") || todayDate(),
    projectId: project.id,
    projectNo: project.projectNo || "",
    projectName: project.name || "",
    milestone: valueOf("scheduleMilestoneSelect") || projectMilestone(project) || "",
    staffRole: currentStaff?.staffRole || valueOf("scheduleStaffRoleSelect") || "PM",
    staffName: currentStaff?.staffName || valueOf("scheduleStaffNameInput").trim(),
    detail,
    createdById: previousEntry?.createdById || assignedProjectUserId(),
    createdByName: previousEntry?.createdByName || assignedProjectUserName(),
    createdAt: previousEntry?.createdAt || new Date().toISOString(),
    completed: scheduleDialogEditId ? checkedOf("scheduleCompletedInput") : false,
  };
  if (scheduleDialogEditId) removeScheduleEntry(scheduleDialogEditId);
  saveScheduleEntryToProject(project, entry);
  focusScheduleCursorOnDate(entry.date);
  try {
    await persistEntry();
  } catch (error) {
    alert(error?.message || "일정을 저장하지 못했습니다.");
    return;
  }
  closeScheduleDialog();
  renderScheduleViews();
  renderProjectSchedules(project);
  renderDashboard();
}

function projectScheduleRows(project) {
  const rows = (project?.schedules || []).map((entry) => normalizeScheduleEntry(project, entry));
  const visibleRows = canViewAllProjectSchedules() ? rows : rows.filter(canViewProjectScheduleEntry);
  return visibleRows.sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")));
}

function renderProjectSchedules(project) {
  const list = $("projectScheduleList");
  if (!list) return;
  const rows = projectScheduleRows(project);
  list.innerHTML = rows.length
    ? rows.map((entry) => {
        const canManageEntry = canManageProjectScheduleEntry(project, entry);
        return `<article class="communication-card project-schedule-card${entry.completed ? " is-schedule-completed" : ""}" data-detail-schedule-id="${escapeAttr(entry.id)}">
        <div class="communication-view">
          <div class="entry-card-head">
            <div class="project-schedule-head entry-card-head-main">
              <label class="project-schedule-complete check-option">
                <input type="checkbox" class="project-schedule-complete-input" data-schedule-entry-id="${escapeAttr(entry.id)}" ${entry.completed ? "checked" : ""} ${canManageEntry ? "" : "disabled"} />
                <span>완료</span>
              </label>
              <span class="project-schedule-date">${escapeHtml(entry.date || "-")}</span>
              <span class="schedule-milestone-badge">${escapeHtml(entry.milestone || "-")}</span>
              <span class="schedule-staff-badge">${escapeHtml(scheduleStaffBadgeText(entry))}</span>
            </div>
            <div class="entry-card-head-actions">
              <button class="ghost-btn project-schedule-edit${canManageEntry ? "" : " hidden"}" type="button">수정</button>
              <button class="ghost-btn danger project-schedule-delete${canManageEntry ? "" : " hidden"}" type="button">삭제</button>
            </div>
          </div>
          <p class="issue-text">${escapeHtml(entry.detail || "일정")}</p>
        </div>
      </article>`;
      }).join("")
    : '<p class="empty">등록된 일정이 없습니다.</p>';
  list.querySelectorAll("[data-detail-schedule-id]").forEach((card) => {
    const entry = rows.find((item) => item.id === card.dataset.detailScheduleId);
    if (!entry) return;
    card.querySelector(".project-schedule-complete-input")?.addEventListener("change", (event) => {
      event.stopPropagation();
      const input = event.target;
      const checked = input.checked;
      if (!toggleScheduleCompleted(input.dataset.scheduleEntryId, checked)) {
        input.checked = !checked;
      }
    });
    card.querySelector(".project-schedule-edit")?.addEventListener("click", () => {
      if (!canManageProjectScheduleEntry(project, entry)) return;
      openScheduleDialog(entry.date || todayDate(), { editingEntry: entry, projectId: project.id });
    });
    card.querySelector(".project-schedule-delete")?.addEventListener("click", () => {
      if (!canManageProjectScheduleEntry(project, entry)) return;
      if (!confirm("이 일정을 삭제할까요?")) return;
      removeScheduleEntry(entry.id);
      persistEntry();
      renderProjectSchedules(project);
      renderScheduleViews();
      renderDashboard();
    });
  });
  applyReadOnlyUi();
}

function openProjectScheduleDropdown() {
  document.querySelector(".project-schedule-dropdown")?.setAttribute("open", "");
}

function addProjectSchedule() {
  const project = selectedProject();
  if (!project) return;
  if (!canCreateProjectSchedule(project)) {
    alert("현재 계정은 이 프로젝트에 일정을 등록할 권한이 없습니다.");
    return;
  }
  openScheduleDialog(todayDate(), { projectId: project.id });
}

function moveScheduleMonth(amount) {
  if (scheduleCalendarMode() === "week") {
    scheduleWeekAnchor = addDays(scheduleWeekAnchor, amount * 7);
    renderScheduleViews();
    return;
  }
  const date = new Date(scheduleCursor.year, scheduleCursor.month - 1 + amount, 1);
  scheduleCursor = { year: date.getFullYear(), month: date.getMonth() + 1 };
  renderScheduleViews();
}

function moveScheduleList(amount) {
  if (scheduleListMode() === "week") {
    scheduleWeekAnchor = addDays(scheduleWeekAnchor, amount * 7);
  } else {
    moveScheduleMonth(amount);
    return;
  }
  renderScheduleListRows();
}

function bindScheduleUi() {
  if (scheduleUiReady) return;
  scheduleUiReady = true;
  on("schedulePrevMonth", "click", () => moveScheduleMonth(-1));
  on("scheduleNextMonth", "click", () => moveScheduleMonth(1));
  on("scheduleListPrev", "click", () => moveScheduleList(-1));
  on("scheduleListNext", "click", () => moveScheduleList(1));
  on("scheduleCalendarMonth", "change", renderScheduleCalendarGrid);
  on("scheduleCalendarWeek", "change", renderScheduleCalendarGrid);
  on("addScheduleFromCalendar", "click", () => {
    if (currentUser && (canManageAllProjectSchedules() || canUseAssignedProjectSchedules())) openScheduleDialog(dateFromParts(scheduleCursor.year, scheduleCursor.month, 1));
  });
  on("addScheduleFromList", "click", () => {
    if (currentUser && (canManageAllProjectSchedules() || canUseAssignedProjectSchedules())) openScheduleDialog(scheduleWeekAnchor);
  });
  on("closeScheduleDialog", "click", closeScheduleDialog);
  on("scheduleForm", "submit", submitScheduleForm);
  on("scheduleSearchInput", "input", renderScheduleViews);
  on("scheduleViewCalendar", "change", renderScheduleViews);
  on("scheduleViewList", "change", renderScheduleViews);
  on("scheduleListMonth", "change", renderScheduleListRows);
  on("scheduleListWeek", "change", renderScheduleListRows);
  on("scheduleProjectSearch", "input", renderScheduleProjectResults);
  on("scheduleMilestoneSelect", "change", () => {
    const project = selectedScheduleProject();
    if (!project) return;
    const staff = scheduleDialogEditId
      ? scheduleStaffForMilestone(project, valueOf("scheduleMilestoneSelect"))
      : scheduleStaffForCurrentUser(project) || scheduleStaffForMilestone(project, valueOf("scheduleMilestoneSelect"));
    setValue("scheduleStaffRoleSelect", staff.staffRole);
    setValue("scheduleStaffNameInput", staff.staffName || "");
  });
  on("scheduleProjectDetailButton", "click", () => {
    const entry = allScheduleEntries().find((item) => item.id === scheduleDialogEditId);
    if (!entry?.projectId) return;
    closeScheduleDialog();
    openProjectDetailOnScheduleView(entry.projectId);
  });
}

function renderLoginLogs() {
  const tbody = $("loginLogRows");
  if (!tbody || !isAdmin()) return;
  const logs = typeof projectRepository?.getLoginLogs === "function" ? projectRepository.getLoginLogs() : [];
  tbody.innerHTML = logs.length
    ? logs.map((log) => `<tr>
        <td>${escapeHtml(log.userId || "-")}</td>
        <td>${escapeHtml(log.name || "-")}</td>
        <td><span class="role-badge ${roleBadgeClass(log.role)}">${escapeHtml(roleLabel(log.role))}</span></td>
        <td><span class="status-badge ${log.result === "success" ? "approved" : "rejected"}">${log.result === "success" ? "성공" : "실패"}</span></td>
        <td>${escapeHtml(log.failureReason || "-")}</td>
        <td>${escapeHtml(log.ip || "-")}</td>
        <td>${escapeHtml(log.createdAt || "-")}</td>
      </tr>`).join("")
    : '<tr><td colspan="7" class="empty-cell">조회된 로그인 로그가 없습니다.</td></tr>';
}

async function refreshLoginLogs() {
  if (!isAdmin() || typeof projectRepository?.refreshLoginLogs !== "function") return;
  try {
    await projectRepository.refreshLoginLogs();
    renderLoginLogs();
  } catch (error) {
    console.error(error);
    const tbody = $("loginLogRows");
    if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">로그인 로그를 불러오지 못했습니다.</td></tr>';
  }
}

function projectLogActionClass(action) {
  const value = String(action || "").trim();
  if (value === "등록") return "log-action-create";
  if (value === "수정") return "log-action-update";
  if (value === "삭제") return "log-action-delete";
  return "pending";
}

function renderProjectLogs() {
  const tbody = $("projectLogRows");
  if (!tbody || !currentUser) return;
  const logs = typeof projectRepository?.getProjectLogs === "function" ? projectRepository.getProjectLogs() : [];
  tbody.innerHTML = logs.length
    ? logs.map((log) => `<tr>
        <td>${escapeHtml(log.userId || "-")}</td>
        <td>${escapeHtml(log.name || "-")}</td>
        <td>${escapeHtml(log.category || "-")}</td>
        <td><span class="status-badge ${projectLogActionClass(log.action)}">${escapeHtml(log.action || "-")}</span></td>
        <td>${escapeHtml(log.projectNo || "-")}</td>
        <td>${escapeHtml(log.projectName || "-")}</td>
        <td class="project-log-summary-cell">${escapeHtml(log.summary || "-")}</td>
        <td>${escapeHtml(log.createdAt || "-")}</td>
      </tr>`).join("")
    : '<tr><td colspan="8" class="empty-cell">조회된 프로젝트 로그가 없습니다.</td></tr>';
  renderProjectLogPagination();
}

function renderProjectLogPagination() {
  const nav = $("projectLogPagination");
  if (!nav || !currentUser) return;
  const meta = typeof projectRepository?.getProjectLogsMeta === "function"
    ? projectRepository.getProjectLogsMeta()
    : { total: 0, page: 1, pageSize: PROJECT_LOG_PAGE_SIZE, totalPages: 1 };
  const page = meta.page || 1;
  const totalPages = meta.totalPages || 1;
  const total = meta.total || 0;
  nav.innerHTML = `
    <button class="ghost-btn table-page-btn" type="button" id="projectLogPrev" ${page <= 1 ? "disabled" : ""}>이전</button>
    <span class="table-page-status">${page} / ${totalPages} · 총 ${total.toLocaleString("ko-KR")}건</span>
    <button class="ghost-btn table-page-btn" type="button" id="projectLogNext" ${page >= totalPages ? "disabled" : ""}>다음</button>
  `;
  $("projectLogPrev")?.addEventListener("click", () => {
    if (page > 1) void goProjectLogPage(page - 1);
  });
  $("projectLogNext")?.addEventListener("click", () => {
    if (page < totalPages) void goProjectLogPage(page + 1);
  });
}

async function goProjectLogPage(page) {
  projectLogPage = Math.max(1, page);
  await refreshProjectLogs(projectLogPage);
}

async function refreshProjectLogs(page = projectLogPage) {
  if (!currentUser || typeof projectRepository?.refreshProjectLogs !== "function") return;
  try {
    projectLogPage = page;
    await projectRepository.refreshProjectLogs(page, PROJECT_LOG_PAGE_SIZE);
    renderProjectLogs();
  } catch (error) {
    console.error(error);
    const tbody = $("projectLogRows");
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">프로젝트 로그를 불러오지 못했습니다.</td></tr>';
    const nav = $("projectLogPagination");
    if (nav) nav.innerHTML = "";
  }
}

const PROJECT_ASSIGNMENT_FILTERS = [
  { id: "projectAssignmentPmFilter", label: "전체 PM", nameField: "pm", idField: "pmId", departments: ["pm"] },
  { id: "projectAssignmentDesignerFilter", label: "전체 디자이너", nameField: "designer", idField: "designerId", departments: ["디자인", "디자이너"] },
  { id: "projectAssignmentPublisherFilter", label: "전체 퍼블리셔", nameField: "publisher", idField: "publisherId", departments: ["퍼블리싱", "퍼블리셔"] },
  { id: "projectAssignmentProgrammerFilter", label: "전체 프로그래머", nameField: "programmer", idField: "programmerId", departments: ["프로그램", "프로그래머"] },
];

function projectAssignmentSource() {
  return isAdmin() ? projects : assignmentProjects;
}

function projectAssignmentSaveSource() {
  return isAdmin() ? projects : assignmentProjects;
}

function canManageProjectAssignment() {
  return isAdmin() || isTeamLead();
}

function projectAssignmentMissing(project, nameField, idField) {
  return !String(project?.[idField] || project?.[nameField] || "").trim();
}

function projectNeedsAssignmentForDepartments(project, departments) {
  const normalized = departments.map((department) => normalizeDepartmentKey(department));
  if (normalized.includes("pm")) {
    return projectAssignmentMissing(project, "pm", "pmId");
  }
  if (normalized.includes("디자인")) {
    return !projectAssignmentMissing(project, "pm", "pmId") && projectAssignmentMissing(project, "designer", "designerId");
  }
  if (normalized.includes("퍼블리싱")) {
    return projectCompletionDone(project, "design_worker", "design_lead", "design_pm") && projectAssignmentMissing(project, "publisher", "publisherId");
  }
  if (normalized.includes("프로그램")) {
    return projectCompletionDone(project, "publishing_worker", "publishing_lead", "publishing_pm") && projectAssignmentMissing(project, "programmer", "programmerId");
  }
  return false;
}

function currentAssignmentDepartments() {
  if (isDepartment("pm")) return ["pm"];
  if (isDepartment("디자인", "디자이너")) return ["디자인", "디자이너"];
  if (isDepartment("퍼블리싱", "퍼블리셔")) return ["퍼블리싱", "퍼블리셔"];
  if (isDepartment("프로그램", "프로그래머")) return ["프로그램", "프로그래머"];
  return [];
}

function projectNeedsAssignmentForCurrentUser(project) {
  if (isAdmin()) return true;
  if (!isTeamLead()) return false;
  const departments = currentAssignmentDepartments();
  return departments.length ? projectNeedsAssignmentForDepartments(project, departments) : false;
}

function projectAssignmentCount() {
  if (!currentUser || !isTeamLead() || isAdmin()) return 0;
  return assignmentProjects.filter(hasProjectNo).filter(projectNeedsAssignmentForCurrentUser).length;
}

function projectAssignmentPending(project) {
  if (isAdmin()) {
    return projectAssignmentMissing(project, "pm", "pmId")
      || projectAssignmentMissing(project, "designer", "designerId")
      || projectAssignmentMissing(project, "publisher", "publisherId")
      || projectAssignmentMissing(project, "programmer", "programmerId");
  }
  return projectNeedsAssignmentForCurrentUser(project);
}

function compareProjectAssignmentRows(a, b) {
  const pendingA = projectAssignmentPending(a);
  const pendingB = projectAssignmentPending(b);
  if (pendingA !== pendingB) return pendingA ? -1 : 1;
  return compareProjectNo(a, b);
}

function canEditProjectAssignmentField(departments) {
  if (isAdmin()) return true;
  if (!isTeamLead()) return false;
  return departments.some((department) => isDepartment(department));
}

function staffByDepartments(...departments) {
  const allowed = departments.map((department) => normalizeDepartmentKey(department));
  const users = typeof projectRepository?.getUsers === "function" ? projectRepository.getUsers() : [];
  return users
    .filter((user) => allowed.includes(normalizeDepartmentKey(user.department || "")))
    .sort((a, b) => String(a.name || "").localeCompare(String(b.name || ""), "ko"));
}

function projectAssignmentSelect(project, nameField, idField, departments) {
  const users = staffByDepartments(...departments);
  const canEdit = canEditProjectAssignmentField(departments);
  const activeUsers = users.filter((user) => user.approvalStatus === "활성화");
  const inactiveUsers = users.filter((user) => user.approvalStatus !== "활성화");
  const currentId = String(project[idField] || "").trim();
  const currentName = String(project[nameField] || "").trim();
  const hasCurrent = users.some((user) => String(user.id || "") === currentId || String(user.name || "") === currentName);
  const optionForUser = (user) => {
    const selected = currentId ? String(user.id || "") === currentId : String(user.name || "") === currentName;
    return `<option value="${escapeAttr(user.id || "")}" data-name="${escapeAttr(user.name || "")}" ${selected ? "selected" : ""}>${escapeHtml(user.name || "-")}</option>`;
  };
  const options = [
    '<option value="">미배정</option>',
    ...activeUsers.map(optionForUser),
  ];
  if (inactiveUsers.length) {
    options.push('<option value="" disabled>──── 퇴사자 ────</option>');
    options.push(...inactiveUsers.map(optionForUser));
  }
  if (currentName && !hasCurrent) {
    options.push(`<option value="${escapeAttr(currentId)}" data-name="${escapeAttr(currentName)}" selected>${escapeHtml(currentName)}</option>`);
  }
  return `<select class="member-dialog-select" data-project-assignment-id="${escapeAttr(project.id)}" data-project-assignment-field="${escapeAttr(nameField)}" data-project-assignment-id-field="${escapeAttr(idField)}" ${canEdit ? "" : "disabled"}>${options.join("")}</select>`;
}

function projectAssignmentFilterValue(project, nameField, idField) {
  return String(project[idField] || project[nameField] || "").trim();
}

function populateProjectAssignmentFilters() {
  PROJECT_ASSIGNMENT_FILTERS.forEach(({ id, label, nameField, idField, departments }) => {
    const select = $(id);
    if (!select) return;
    const current = select.value || "";
    const users = staffByDepartments(...departments);
    const seen = new Set();
    const options = [`<option value="">${escapeHtml(label)}</option>`];
    users.forEach((user) => {
      const value = String(user.id || user.name || "").trim();
      if (!value || seen.has(value)) return;
      seen.add(value);
      const suffix = user.approvalStatus === "활성화" ? "" : " (퇴사)";
      options.push(`<option value="${escapeAttr(value)}">${escapeHtml(`${user.name || "-"}${suffix}`)}</option>`);
    });
    [...new Set(projectAssignmentSource().map((project) => projectAssignmentFilterValue(project, nameField, idField)).filter(Boolean))].forEach((value) => {
      if (!seen.has(value)) options.push(`<option value="${escapeAttr(value)}">${escapeHtml(value)}</option>`);
    });
    select.innerHTML = options.join("");
    select.value = [...select.options].some((option) => option.value === current) ? current : "";
  });
}

function filteredProjectAssignmentRows() {
  const query = valueOf("projectAssignmentSearchInput").trim().toLowerCase();
  return [...projectAssignmentSource()].filter(hasProjectNo).filter((project) => {
    const haystack = [project.projectNo, project.name].map((value) => String(value || "").toLowerCase()).join(" ");
    if (query && !haystack.includes(query)) return false;
    return PROJECT_ASSIGNMENT_FILTERS.every(({ id, nameField, idField }) => {
      const filterValue = valueOf(id).trim();
      if (!filterValue) return true;
      return projectAssignmentFilterValue(project, nameField, idField) === filterValue;
    });
  });
}

function openProjectAssignmentDetail(projectId) {
  if (!projectId) return;
  cancelCreateProject();
  selectedId = projectId;
  document.body.classList.remove("schedule-detail-open");
  document.body.classList.add("detail-open");
  closeDetailDropdowns();
  renderAll(false);
  saveUiSessionState();
}

function renderProjectCompletionRows() {
  const tbody = $("projectCompletionApprovalRows");
  if (!tbody) return;
  if (!currentUser) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">로그인 후 확인할 수 있습니다.</td></tr>';
    return;
  }
  const rows = projectCompletionRowsForCurrentUser().sort(compareProjectNo);
  tbody.innerHTML = rows.length
    ? rows
        .map((project) => {
          const stage = projectCompletionStage(project);
          return `<tr data-project-completion-row="${escapeAttr(project.id)}" tabindex="0">
            <td>${escapeHtml(project.projectNo || "-")}</td>
            <td>${escapeHtml(project.name || "-")}</td>
            <td>${escapeHtml(projectCompletionActorName(project, stage))}</td>
            <td>${escapeHtml(projectCompletionProgressLabel(project, stage))}</td>
            <td>
              <div class="completion-action-group">
                <button class="ghost-btn table-action" type="button" data-project-completion-action="approve" data-project-completion-id="${escapeAttr(project.id)}">승인</button>
                <button class="ghost-btn danger table-action" type="button" data-project-completion-action="reject" data-project-completion-id="${escapeAttr(project.id)}">반려</button>
              </div>
            </td>
          </tr>`;
        })
        .join("")
    : '<tr><td colspan="5" class="empty-cell">완료 처리할 프로젝트가 없습니다.</td></tr>';
  tbody.querySelectorAll("[data-project-completion-row]").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest("button")) return;
      openProjectDetail(row.dataset.projectCompletionRow);
    });
  });
}

function completeSelectedProjectStage() {
  const project = selectedProject();
  const stage = projectCompletionStage(project);
  if (!project || !stage || !canCompleteProjectFromDetail(project)) return;
  if (stage.actor === "worker") {
    openProjectCompletionDialog();
    return;
  }
  if (!confirm("완료 처리하시겠습니까?")) return;
  void advanceProjectCompletion(project.id, "approve");
}

async function advanceProjectCompletion(projectId, action = "approve", completionType = "", memo = "") {
  try {
    let reason = "";
    if (action === "reject") {
      reason = prompt("반려 사유를 입력해주세요.")?.trim() || "";
      if (!reason) {
        alert("반려 사유를 입력해주세요.");
        return;
      }
    }
    const snapshot = await projectRepository.advanceProjectCompletion(projectId, action, reason, completionType, memo);
    updateStateFromSnapshot(snapshot, { keepSelected: true });
    renderAll(false);
  } catch (error) {
    alert(error?.message || "프로젝트 완료 상태를 저장하지 못했습니다.");
  }
}

function renderProjectAssignmentRows() {
  const tbody = $("projectAssignmentRows");
  if (!tbody) return;
  if (!canManageProjectAssignment()) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">관리자 또는 팀장만 확인할 수 있습니다.</td></tr>';
    return;
  }
  populateProjectAssignmentFilters();
  const rows = filteredProjectAssignmentRows().sort(compareProjectAssignmentRows);
  tbody.innerHTML = rows.length
    ? rows
        .map(
          (project) => `<tr class="${projectAssignmentPending(project) ? "is-assignment-pending" : "is-assignment-complete"}" data-project-assignment-row="${escapeAttr(project.id)}" tabindex="0">
            <td>${escapeHtml(project.projectNo || "-")}</td>
            <td>${escapeHtml(project.name || "-")}</td>
            <td>${projectAssignmentSelect(project, "pm", "pmId", ["pm"])}</td>
            <td>${projectAssignmentSelect(project, "designer", "designerId", ["디자인", "디자이너"])}</td>
            <td>${projectAssignmentSelect(project, "publisher", "publisherId", ["퍼블리싱", "퍼블리셔"])}</td>
            <td>${projectAssignmentSelect(project, "programmer", "programmerId", ["프로그램", "프로그래머"])}</td>
          </tr>`
        )
        .join("")
    : '<tr><td colspan="6" class="empty-cell">표시할 프로젝트가 없습니다.</td></tr>';
  tbody.querySelectorAll("[data-project-assignment-row]").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest("select, button, input, a")) return;
      event.stopPropagation();
      openProjectAssignmentDetail(row.dataset.projectAssignmentRow);
    });
    row.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      if (event.target.closest("select, button, input, a")) return;
      event.preventDefault();
      openProjectAssignmentDetail(row.dataset.projectAssignmentRow);
    });
  });
}


function renderAll(includeFilters = true) {
  if (includeFilters) renderFilters();
  renderDashboard();
  renderRows();
  renderMonthlyRows();
  renderIssueProjectRows();
  renderProjectAssignmentRows();
  renderProjectCompletionRows();
  updateProjectCompletionNavCount();
  updateProjectAssignmentNavCount();
  renderBasicManagement();
  renderDepartments();
  renderLeaveManagement();
  renderLeaveApprovals();
  renderVacationSchedule();
  renderLoginLogs();
  if (currentView === "projectLogs" && currentUser) void refreshProjectLogs(projectLogPage);
  renderScheduleViews();
  renderDetail();
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    if (!currentUser && (button.dataset.authMenu === "attendance" || button.dataset.authMenu === "basic")) {
      alert("로그인 후 확인 가능합니다.");
      return;
    }
    if (button.dataset.view === "projects") {
      openProjectsList({ resetFilters: true });
      return;
    }
    switchView(button.dataset.view);
    if (button.dataset.view === "members") {
      void refreshMemberManagementData();
    }
    if (button.dataset.view === "loginLogs") refreshLoginLogs();
    if (button.dataset.view === "departments") refreshDepartments();
    if (button.dataset.view === "projectLogs") {
      projectLogPage = 1;
      refreshProjectLogs(1);
    }
    if (button.dataset.view === "leaveManagement") refreshLeaves();
    if (button.dataset.view === "leaveApprovals") refreshLeaveApprovals();
    if (button.dataset.view === "vacationSchedule") refreshVacationSchedule();
    if (button.dataset.view === "schedule") renderScheduleViews();
  });
});

document.querySelectorAll("[data-view-shortcut]").forEach((button) => {
  button.addEventListener("click", () => {
    if (button.dataset.viewShortcut === "projects") {
      openProjectsList({ resetFilters: true });
      return;
    }
    switchView(button.dataset.viewShortcut);
  });
});

document.addEventListener("input", (event) => {
  if (event.target.id === "projectNo") {
    const digits = event.target.value.replace(/\D/g, "");
    if (event.target.value !== digits) event.target.value = digits;
  }
  if (event.target.closest(".detail-main-grid")) updateDetailFilledState();
  if (event.target.id === "searchInput") renderRows();
  if (event.target.id === "projectAssignmentSearchInput") renderProjectAssignmentRows();
  if (event.target.id === "memberSearchInput") renderBasicManagement();
  if (event.target.id === "detailSearchInput") {
    const project = selectedProject();
    if (!project) return;
    renderIssues(project);
    renderCommunications(project);
  }
  if (event.target.id === "vacationSearchInput") renderVacationSchedule();
});

document.addEventListener("change", (event) => {
  const assignmentSelect = event.target.closest?.("[data-project-assignment-field]");
  if (assignmentSelect) {
    const fieldConfig = PROJECT_ASSIGNMENT_FILTERS.find(({ nameField, idField }) => nameField === assignmentSelect.dataset.projectAssignmentField && idField === assignmentSelect.dataset.projectAssignmentIdField);
    if (!fieldConfig || !canEditProjectAssignmentField(fieldConfig.departments)) {
      renderProjectAssignmentRows();
      return;
    }
    const project = projectAssignmentSaveSource().find((item) => item.id === assignmentSelect.dataset.projectAssignmentId);
    if (!project || !canManageProjectAssignment()) return;
    const nameField = assignmentSelect.dataset.projectAssignmentField;
    const idField = assignmentSelect.dataset.projectAssignmentIdField;
    const selectedOption = assignmentSelect.selectedOptions?.[0];
    const previousValue = String(project[idField] || project[nameField] || "").trim();
    const nextValue = String(assignmentSelect.value || "").trim();
    const assignedAtField = `${nameField}AssignedAt`;
    project[idField] = assignmentSelect.value || "";
    project[nameField] = assignmentSelect.value ? selectedOption?.dataset.name || selectedOption?.textContent?.trim() || "" : "";
    if (previousValue !== nextValue) project[assignedAtField] = nextValue ? new Date().toISOString() : "";
    const localProject = projects.find((item) => item.id === project.id);
    if (localProject) {
      localProject[idField] = project[idField];
      localProject[nameField] = project[nameField];
      localProject[assignedAtField] = project[assignedAtField] || "";
    }
    void projectRepository.saveProjectAssignments(projectAssignmentSaveSource()).then((result) => {
      if (result.projects) projects = result.projects.map(normalizeProject).filter(hasProjectNo);
      if (result.assignmentProjects) assignmentProjects = result.assignmentProjects.map(normalizeProject).filter(hasProjectNo);
      if (result.scheduleProjects) scheduleProjects = result.scheduleProjects.map(normalizeProject).filter(hasProjectNo);
      renderRows();
      renderProjectAssignmentRows();
      updateProjectAssignmentNavCount();
      renderScheduleViews();
      renderDetail();
    }).catch((error) => {
      alert(error?.message || "프로젝트 배정을 저장하지 못했습니다.");
      renderProjectAssignmentRows();
      updateProjectAssignmentNavCount();
    });
    return;
  }
  if (event.target.closest(".detail-main-grid")) updateDetailFilledState();
  if (event.target.id === "hasIssue" || event.target.id === "monthlyCollection") updateDetailHeaderChecks();
  if (event.target.id === "pmFilter") {
    progressStatusFilter = "";
    milestoneFilter = "";
    renderRows();
  }
  if (event.target.id?.startsWith("projectAssignment") && event.target.id.endsWith("Filter")) renderProjectAssignmentRows();
  if (event.target.id === "memberDepartmentFilter") renderBasicManagement();
  if (event.target.name === "vacationScheduleViewMode") renderVacationSchedule();
  if (event.target.name === "vacationListPeriod") renderVacationScheduleRows();
});

on("departmentAddBtn", "click", addDepartment);
on("vacationLeaveAddBtn", "click", openVacationLeaveDialog);
on("vacationLeaveAddBtnList", "click", openVacationLeaveDialog);
on("closeVacationLeaveDialog", "click", closeVacationLeaveDialog);
on("vacationLeaveForm", "submit", submitVacationLeaveForm);
on("vacationLeaveUserSearch", "input", () => {
  selectedVacationLeaveUserId = "";
  setValue("vacationLeaveUserId", "");
  renderVacationLeaveUserResults();
});
on("companyHolidayAddBtn", "click", () => openCompanyHolidayDialog());
on("companyHolidayAddBtnList", "click", () => openCompanyHolidayDialog());
on("closeCompanyHolidayDialog", "click", closeCompanyHolidayDialog);
on("companyHolidayForm", "submit", saveCompanyHoliday);
on("companyHolidayDeleteBtn", "click", deleteCompanyHoliday);

document.addEventListener("click", (event) => {
  const completionTarget = event.target.closest?.("[data-project-completion-action]");
  if (completionTarget) {
    void advanceProjectCompletion(completionTarget.dataset.projectCompletionId, completionTarget.dataset.projectCompletionAction || "approve");
    return;
  }
  const holidayTarget = event.target.closest?.("[data-company-holiday-id]");
  if (holidayTarget) openCompanyHolidayDialog(holidayTarget.dataset.companyHolidayId);
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const completionTarget = event.target.closest?.("[data-project-completion-action]");
  if (completionTarget) {
    void advanceProjectCompletion(completionTarget.dataset.projectCompletionId, completionTarget.dataset.projectCompletionAction || "approve");
    return;
  }
  const holidayTarget = event.target.closest?.("[data-company-holiday-id]");
  if (!holidayTarget) return;
  event.preventDefault();
  openCompanyHolidayDialog(holidayTarget.dataset.companyHolidayId);
});

on("detailSearchInput", "keydown", (event) => {
  if (event.key === "Enter") event.preventDefault();
});

on("milestoneFilterToggle", "click", (event) => {
  event.stopPropagation();
  setMilestoneFilterOpen(!$("milestoneFilterWrap")?.classList.contains("open"));
});
on("milestoneFilterMenu", "click", (event) => event.stopPropagation());
on("milestoneFilterMenu", "change", (event) => {
  if (event.target.type !== "checkbox") return;
  progressStatusFilter = "";
  milestoneFilter = "";
  updateMilestoneFilterLabel();
  renderRows();
});

on("statusFilterToggle", "click", (event) => {
  event.stopPropagation();
  setStatusFilterOpen(!$("statusFilterWrap")?.classList.contains("open"));
});
on("statusFilterMenu", "click", (event) => event.stopPropagation());
on("statusFilterMenu", "change", (event) => {
  if (event.target.type !== "checkbox") return;
  progressStatusFilter = "";
  milestoneFilter = "";
  updateStatusFilterLabel();
  renderRows();
});

on("projectOptionFilterToggle", "click", (event) => {
  event.stopPropagation();
  setProjectOptionFilterOpen(!$("projectOptionFilterWrap")?.classList.contains("open"));
});
on("projectOptionFilterMenu", "click", (event) => event.stopPropagation());
on("projectOptionFilterMenu", "change", (event) => {
  if (event.target.type !== "checkbox") return;
  progressStatusFilter = "";
  milestoneFilter = "";
  updateProjectOptionFilterLabel();
  renderRows();
});

document.addEventListener("click", (event) => {
  const sortTrigger = event.target.closest("[data-sort-list][data-sort-key]");
  if (sortTrigger) {
    toggleListSort(sortTrigger.dataset.sortList, sortTrigger.dataset.sortKey);
    return;
  }
  closeListFilterMenus();
  if (!document.body.classList.contains("detail-open")) return;
  const target = event.target instanceof Element ? event.target : event.target?.parentElement;
  if (!target?.closest) return;
  if (target.closest("#detailForm")) return;
  if (target.closest("dialog")) return;
  if (target.closest("#newProject")) return;
  if (target.closest("#projectRows tr")) return;
  if (target.closest("#monthlyRows tr")) return;
  if (target.closest("[data-schedule-entry-id]")) return;
  closeDetail();
});

on("detailForm", "click", (event) => {
  event.stopPropagation();
  closeListFilterMenus();
});
on("detailForm", "submit", (event) => {
  event.preventDefault();
  saveDetail();
});
on("saveDetailBtn", "click", (event) => {
  event.preventDefault();
  event.stopPropagation();
  saveDetail();
});
on("deleteProject", "click", (event) => {
  event.preventDefault();
  event.stopPropagation();
  deleteSelectedProject();
});
on("downloadProjectsData", "click", (event) => {
  event.stopPropagation();
  openDownloadDialog();
});
on("downloadMembersExcelBtn", "click", (event) => {
  event.stopPropagation();
  downloadMembersExcel();
});
on("downloadForm", "submit", submitDownloadForm);
on("closeDownload", "click", closeDownloadDialog);
on("newProject", "click", (event) => {
  event.stopPropagation();
  addProject();
});
on("closeDetail", "click", (event) => {
  event.stopPropagation();
  closeDetail();
});
on("sidebarRail", "click", toggleSidebar);
on("addIssue", "click", addIssue);
on("addClientContact", "click", addClientContact);
on("addCommunication", "click", addCommunication);
on("addProjectSchedule", "click", addProjectSchedule);
on("projectCompleteAction", "click", completeSelectedProjectStage);
on("closeProjectCompletionDialog", "click", closeProjectCompletionDialog);
on("projectCompletionForm", "submit", submitProjectCompletionDialog);
on("quoteFile", "change", handlePdfUpload);
on("quoteAction", "click", handleQuoteAction);
on("shortcutAction", "click", () => openProjectLink(selectedProject(), "shortcutUrl"));
on("intranetAction", "click", () => openProjectLink(selectedProject(), "intranetUrl"));
on("designAction", "click", () => openProjectLink(selectedProject(), "designUrl"));
on("shortcutForm", "submit", submitShortcutUrl);
on("closeShortcut", "click", () => $("shortcutDialog")?.close());
on("loginButton", "click", openLogin);
on("logoutButton", "click", logout);
on("loginForm", "submit", submitLogin);
on("closeLogin", "click", () => {
  if (!currentUser) return;
  $("loginDialog")?.close();
});
$("loginDialog")?.addEventListener("cancel", (event) => {
  if (!currentUser) event.preventDefault();
});
on("addMemberBtn", "click", () => openMemberDialog());
on("memberForm", "submit", submitMemberForm);
on("closeMemberDialog", "click", closeMemberDialog);
on("addLeaveRequestBtn", "click", openLeaveDialog);
on("leaveForm", "submit", submitLeaveForm);
on("closeLeaveDialog", "click", closeLeaveDialog);
on("leaveUserSearch", "input", () => {
  selectedLeaveUserId = "";
  setValue("leaveUserId", "");
  renderLeaveUserResults();
});
["leaveStartDate", "leaveEndDate", "leaveType"].forEach((id) => {
  on(id, "change", updateLeaveDaysFromDates);
});
["vacationLeaveStartDate", "vacationLeaveEndDate", "vacationLeaveType"].forEach((id) => {
  on(id, "change", updateVacationLeaveDaysFromDates);
});
on("vacationPrevMonth", "click", () => moveVacationMonth(-1));
on("vacationNextMonth", "click", () => moveVacationMonth(1));
on("vacationListPrev", "click", () => moveVacationList(-1));
on("vacationListNext", "click", () => moveVacationList(1));
on("vacationCalendarMonth", "change", renderVacationCalendarGrid);
on("vacationCalendarWeek", "change", renderVacationCalendarGrid);
on("statusForm", "submit", submitStatusChange);
on("closeStatus", "click", () => $("statusDialog")?.close());

async function hydrateRestoredViewData() {
  try {
    if (currentView === "vacationSchedule" && currentUser) {
      if (isAdmin() && typeof projectRepository?.refreshDepartments === "function") await projectRepository.refreshDepartments();
      if (typeof projectRepository?.refreshVacationSchedule === "function") await projectRepository.refreshVacationSchedule();
    }
    if (currentView === "leaveApprovals" && isAdmin() && typeof projectRepository?.refreshLeaveApprovals === "function") {
      await projectRepository.refreshLeaveApprovals();
    }
    if (currentView === "departments" && isAdmin() && typeof projectRepository?.refreshDepartments === "function") {
      await projectRepository.refreshDepartments();
    }
    if (currentView === "members" && isAdmin()) {
      if (typeof projectRepository?.refreshDepartments === "function") await projectRepository.refreshDepartments();
      if (typeof projectRepository?.refreshUsers === "function") await projectRepository.refreshUsers();
    }
    if (currentView === "loginLogs" && isAdmin() && typeof projectRepository?.refreshLoginLogs === "function") {
      await projectRepository.refreshLoginLogs();
    }
  } catch (error) {
    console.error(error);
  }
}

async function initializeApp() {
  if (!projectRepository) {
    throw new Error("Project data repository is not configured.");
  }
  const snapshot = await projectRepository.initialize();
  updateStateFromSnapshot(snapshot);
  currentUser = snapshot.currentUser || (loginUser ? projectRepository.findUser(loginUser) : currentUser);
  restoreLogin();
  selectedId = accessibleProjects()[0]?.id || null;
  restoreUiSessionState();
  if (!loginUser && projectRepository.mode === "private") {
    await applyDatasetMode("public");
    return;
  }
  await hydrateRestoredViewData();
  renderAll();
  syncProjectsPersistSnapshot(projects);
}

renderClock();
setInterval(renderClock, 1000);
window.addEventListener("resize", syncSidebarWidthToClock);
initializeApp().catch((error) => {
  console.error(error);
  alert("프로젝트 데이터를 불러오지 못했습니다. 데이터 파일을 확인해 주세요.");
});
