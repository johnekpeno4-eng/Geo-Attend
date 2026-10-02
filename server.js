const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const QRCode = require("qrcode");
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require("@simplewebauthn/server");
const { createFingerprintCheckin } = require("./fingerprint-checkin");


const ROOT = __dirname;
loadEnv();

const PORT = Number(process.env.PORT || 5501);
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_COOLDOWN_SECONDS = 60;
const DATA_DIR = path.join(ROOT, "data");
const SQLITE_DB_FILE = path.join(DATA_DIR, "geoattend.db");
const BIOMETRIC_PROFILES_FILE = path.join(DATA_DIR, "biometric-profiles.json");
const LIVE_SESSIONS_FILE = path.join(DATA_DIR, "live-sessions.json");
const ADMIN_LOGIN_AUDIT_FILE = path.join(DATA_DIR, "admin-login-audit.json");
const STUDENT_REPORTS_FILE = path.join(DATA_DIR, "student-reports.json");
const STUDENT_PRESENCE_FILE = path.join(DATA_DIR, "student-presence.json");
const ATTENDANCE_LOG_FILE = path.join(DATA_DIR, "attendance-log.json");
const STUDENTS_FILE = path.join(DATA_DIR, "students.json");
const REGISTRATION_RESET_FILE = path.join(DATA_DIR, "registration-reset.json");
const ADMIN_USERS_FILE = path.join(DATA_DIR, "admin-users.json");
const ATTENDANCE_REPORTS_DIR = path.join(DATA_DIR, "attendance-reports");
const ATTENDANCE_REPORTS_INDEX_FILE = path.join(DATA_DIR, "attendance-reports.json");
const BACKUP_DIR = path.join(DATA_DIR, "backups");
const SERVER_OUT_LOG = path.join(ROOT, "server.out.log");
const SERVER_ERR_LOG = path.join(ROOT, "server.err.log");
const A4_PDF_WIDTH = 595.28;
const A4_PDF_HEIGHT = 841.89;
const otpStore = new Map();
const otpAttemptStore = new Map();
const loginAttemptStore = new Map();
const totpSetupStore = new Map();
const webAuthnChallengeStore = new Map();
const attendanceAuthorizationStore = new Map();
const attendanceActionLocks = new Set();
const fingerprintCheckin = createFingerprintCheckin({ dbRun, dbGet, dbAll, ensureColumn, readLiveSessionsStore, writeAttendanceStore, json, verifyAdminCredentials });


const MIN_GEOFENCE_RADIUS_METERS = 20;
const MAX_GEOFENCE_RADIUS_METERS = 5000;
function getDefaultAcademicSession(date = new Date()) {
  const year = date.getFullYear() - (date.getMonth() < 7 ? 1 : 0);
  return `${year}/${year + 1}`;
}
const DEFAULT_ACADEMIC_SESSION = getDefaultAcademicSession();
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || crypto.randomBytes(32).toString("hex");
let mailTransporter = null;
let sqliteDb = null;

const ACADEMIC_SCOPE = {
  institution: { id: "university-of-uyo", name: "University of Uyo" },
  faculties: [
    { id: "engineering", name: "Faculty of Engineering" },
    { id: "science", name: "Faculty of Science" },
    { id: "agriculture", name: "Faculty of Agriculture" },
    { id: "education", name: "Faculty of Education" }
  ],
  departments: [
    { id: "electrical-electronics-engineering", facultyId: "engineering", name: "Department of Electrical/Electronics Engineering", regPrefix: "25/EG/EE/" },
    { id: "mechanical-engineering", facultyId: "engineering", name: "Department of Mechanical Engineering", regPrefix: "25/EG/ME/" },
    { id: "civil-engineering", facultyId: "engineering", name: "Department of Civil Engineering", regPrefix: "25/EG/CE/" },
    { id: "computer-science", facultyId: "science", name: "Department of Computer Science", regPrefix: "25/SC/CS/" },
    { id: "chemistry", facultyId: "science", name: "Department of Chemistry", regPrefix: "25/SC/CH/" }
  ],
  levels: [
    { id: "100", name: "100 Level" },
    { id: "200", name: "200 Level" },
    { id: "300", name: "300 Level" },
    { id: "400", name: "400 Level" },
    { id: "500", name: "500 Level" }
  ],
  courses: [
    { code: "CHM121", title: "General Chemistry II", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "CHM128", title: "General Practical Chemistry II", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "GET121", title: "Engineering Graphics And Solid Modelling I", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "GST121", title: "Nigerian Peoples And Culture", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "MTH121", title: "Elementary Mathematics II", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "PHY121", title: "General Physics II", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "PHY128", title: "General Practical Physics II", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "UUY-MTH122", title: "Elementary Mathematics III", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "UUY-PHY122", title: "General Physics IV", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" },
    { code: "UUY-STA121", title: "Probability I", facultyId: "engineering", departmentId: "electrical-electronics-engineering", levelId: "100" }
  ]
};

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".pdf": "application/pdf"
};

const server = http.createServer(async (req, res) => {
  try {
    setCorsHeaders(res);

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === "POST" && req.url === "/api/totp-registration-setup") {
      const body = await readJson(req);
      await setupRegistrationTotp(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/verify-registration-totp") {
      const body = await readJson(req);
      verifyRegistrationTotp(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/send-registration-otp") {
      const body = await readJson(req);
      await sendOtp(res, String(body.email || "").trim().toLowerCase(), "registration", String(body.fullName || ""));
      return;
    }

    if (req.method === "POST" && req.url === "/api/verify-registration-otp") {
      const body = await readJson(req);
      verifyOtp(res, String(body.email || "").trim().toLowerCase(), body.otp, "registration");
      return;
    }

    if (req.method === "POST" && req.url === "/api/send-password-reset-otp") {
      const body = await readJson(req);
      await sendPasswordResetOtp(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/verify-password-reset-otp") {
      const body = await readJson(req);
      await verifyPasswordResetOtp(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/verify-password-reset-totp") {
      const body = await readJson(req);
      await verifyPasswordResetTotp(res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/academic-scope")) {
      await getAcademicScope(req, res);
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/academic-session")) {
      await getAcademicSession(req, res);
      return;
    }
    if (req.method === "POST" && req.url === "/api/academic-session") {
      const body = await readJson(req);
      await setAcademicSession(res, body);
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/lecturer-assignments")) {
      await getLecturerAssignments(req, res);
      return;
    }
    if (req.method === "POST" && req.url === "/api/lecturer-assignments") {
      const body = await readJson(req);
      await saveLecturerCourseAssignment(res, body);
      return;
    }
    if (req.method === "DELETE" && req.url.startsWith("/api/lecturer-assignments")) {
      await deleteLecturerCourseAssignment(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/api/courses") {
      await getCourses(req, res);
      return;
    }
    if (req.method === "POST" && req.url === "/api/courses") {
      const body = await readJson(req);
      await saveCourse(res, body);
      return;
    }
    if (req.method === "DELETE" && req.url.startsWith("/api/courses")) {
      await deleteCourse(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/api/webauthn/context") {
      json(res, 200, getWebAuthnContextDiagnostic(req));
      return;
    }

    if (req.method === "POST" && req.url === "/api/webauthn/register-options") {
      const body = await readJson(req);
      await getWebAuthnRegistrationOptions(req, res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/webauthn/register-verify") {
      const body = await readJson(req);
      await verifyWebAuthnRegistration(req, res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/webauthn/login-options") {
      const body = await readJson(req);
      await getWebAuthnLoginOptions(req, res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/webauthn/login-verify") {
      const body = await readJson(req);
      await verifyWebAuthnLogin(req, res, body);
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/webauthn/status")) {
      const identifier = new URL(req.url, `http://${req.headers.host}`).searchParams.get("email") || "";
      await getWebAuthnStatus(res, identifier);
      return;
    }

    if (req.method === "POST" && req.url === "/api/webauthn/remove") {
      const body = await readJson(req);
      await removeWebAuthnCredential(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/save-biometric-profile") {
      const body = await readJson(req);
      await saveBiometricProfile(res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/biometric-profile")) {
      await getBiometricProfile(req, res);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/live-sessions")) {
      await getLiveSessions(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/live-sessions") {
      const body = await readJson(req);
      await saveLiveSession(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/live-sessions/end") {
      const body = await readJson(req);
      await endLiveSession(res, body.sessionId);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/attendance-reports")) {
      getAttendanceReports(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/attendance-reports/add-name") {
      const body = await readJson(req);
      addManualAttendanceReportName(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/attendance-reports/delete") {
      const body = await readJson(req);
      deleteAttendanceReport(res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/attendance-report-file")) {
      serveSavedAttendanceReport(req, res);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/attendance-pdf")) {
      serveAttendancePdf(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/checkin/challenge") {
      const body = await readJson(req);
      await fingerprintCheckin.challenge(req, res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/checkin/scan") {
      const body = await readJson(req);
      await fingerprintCheckin.scan(req, res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/fingerprint/enroll") {
      const body = await readJson(req);
      await fingerprintCheckin.enroll(req, res, body);
      return;
    }

    if (req.url.startsWith("/api/devices") || req.url.startsWith("/api/device/")) {
      const body = ["POST", "PUT", "DELETE"].includes(req.method) ? await readJson(req) : {};
      await handleFingerprintDeviceApi(req, res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/student-device/bind") {
      const body = await readJson(req);
      if (!await authenticateFingerprintDevice(req, String(body.espId || ""))) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
      await bindStudentDevice(res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/attendance")) {
      await getAttendance(req, res);
      return;
    }
    if (req.url.startsWith("/api/assisted-approval")) {
      json(res, 410, { error: "Student-assisted check-in is disabled. Each student must check in personally." });
      return;
    }

    if (req.method === "POST" && req.url === "/api/attendance") {
      const body = await readJson(req);
      await saveAttendance(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/live-sessions/cancel") {
      const body = await readJson(req);
      await cancelLiveSession(res, body);
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/buildings")) {
      await getBuildings(req, res);
      return;
    }
    if (req.method === "POST" && req.url === "/api/buildings") {
      const body = await readJson(req);
      await saveBuilding(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/buildings/delete") {
      const body = await readJson(req);
      await deleteBuilding(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/attendance/status") {
      const body = await readJson(req);
      await updateAttendanceStatus(req, res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/student-presence")) {
      await getStudentPresence(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/student-presence") {
      const body = await readJson(req);
      await updateStudentPresence(res, body);
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/student-reports")) {
      await getStudentReports(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/student-reports") {
      const body = await readJson(req);
      await createStudentReport(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/student-reports/status") {
      const body = await readJson(req);
      await updateStudentReportStatus(res, body);
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/students")) {
      await getStudents(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/api/registration-reset") {
      getRegistrationReset(res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/students/delete") {
      const body = await readJson(req);
      await deleteStudentAccount(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/students") {
      const body = await readJson(req);
      await saveStudent(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/admin-login") {
      const body = await readJson(req);
      await adminLogin(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/student-login") {
      const body = await readJson(req);
      await studentLogin(res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/admins")) {
      getAdmins(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/admins") {
      const body = await readJson(req);
      await saveAdminUser(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/admins/remove") {
      const body = await readJson(req);
      removeAdminUser(res, body);
      return;
    }
    if (req.method === "POST" && req.url === "/api/backup") {
      const body = await readJson(req);
      createBackup(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/admin-login-audit") {
      const body = await readJson(req);
      saveAdminLoginAudit(req, res, body);
      return;
    }

    if (req.method === "GET" && req.url === "/api/config/google-maps") {
      googleMapsConfig(res);
      return;
    }

    serveStatic(req, res);
  } catch (error) {
    json(res, 500, { error: error.message || "Server error" });
  }
});

initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`GeoAttend running at http://127.0.0.1:${PORT}/login.html`);
    console.log(`SQLite database active at ${SQLITE_DB_FILE}`);
  });
}).catch((error) => {
  console.error("SQLite database failed to initialize:", error);
  process.exit(1);
});

function loadEnv() {
  const envPath = path.join(ROOT, ".env");
  if (!fs.existsSync(envPath)) return;

  fs.readFileSync(envPath, "utf8")
    .split(/\r?\n/)
    .forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return;
      const equalsIndex = trimmed.indexOf("=");
      if (equalsIndex === -1) return;
      const key = trimmed.slice(0, equalsIndex).trim();
      const value = trimmed.slice(equalsIndex + 1).trim().replace(/^["']|["']$/g, "");
      if (!process.env[key]) process.env[key] = value;
    });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    sqliteDb.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    sqliteDb.get(sql, params, (error, row) => {
      if (error) reject(error);
      else resolve(row || null);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    sqliteDb.all(sql, params, (error, rows) => {
      if (error) reject(error);
      else resolve(rows || []);
    });
  });
}

async function ensureColumn(table, column, definition) {
  const columns = await dbAll(`PRAGMA table_info(${table})`);
  if (!columns.some((item) => item.name === column)) {
    await dbRun(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function seedAcademicScope() {
  for (const faculty of ACADEMIC_SCOPE.faculties) {
    await dbRun("INSERT OR IGNORE INTO academic_faculties (id, name) VALUES (?, ?)", [faculty.id, faculty.name]);
  }
  for (const department of ACADEMIC_SCOPE.departments) {
    await dbRun("INSERT OR IGNORE INTO academic_departments (id, faculty_id, name, reg_prefix) VALUES (?, ?, ?, ?)", [department.id, department.facultyId, department.name, department.regPrefix]);
  }
  for (const level of ACADEMIC_SCOPE.levels) {
    await dbRun("INSERT OR IGNORE INTO academic_levels (id, name) VALUES (?, ?)", [level.id, level.name]);
  }
  for (const course of ACADEMIC_SCOPE.courses) {
    await dbRun("INSERT OR IGNORE INTO academic_courses_by_session (code, academic_session, title, faculty_id, department_id, level_id) VALUES (?, ?, ?, ?, ?, ?)", [course.code, DEFAULT_ACADEMIC_SESSION, course.title, course.facultyId, course.departmentId, course.levelId]);
  }
}

function getAcademicDefaults() {
  const faculty = ACADEMIC_SCOPE.faculties[0];
  const department = ACADEMIC_SCOPE.departments.find((item) => item.facultyId === faculty.id) || ACADEMIC_SCOPE.departments[0];
  const level = ACADEMIC_SCOPE.levels[0];
  return {
    institutionId: ACADEMIC_SCOPE.institution.id,
    institutionName: ACADEMIC_SCOPE.institution.name,
    facultyId: faculty.id,
    facultyName: faculty.name,
    departmentId: department.id,
    departmentName: department.name,
    levelId: level.id,
    levelName: level.name,
    regPrefix: department.regPrefix
  };
}

function normalizeAcademicScope(input = {}) {
  const defaults = getAcademicDefaults();
  const faculty = ACADEMIC_SCOPE.faculties.find((item) => item.id === input.facultyId || item.name === input.facultyName)
    || ACADEMIC_SCOPE.faculties.find((item) => item.id === defaults.facultyId);
  const department = ACADEMIC_SCOPE.departments.find((item) => item.id === input.departmentId || item.name === input.departmentName)
    || ACADEMIC_SCOPE.departments.find((item) => item.facultyId === faculty.id)
    || ACADEMIC_SCOPE.departments[0];
  const level = ACADEMIC_SCOPE.levels.find((item) => item.id === String(input.levelId || "") || item.name === input.levelName)
    || ACADEMIC_SCOPE.levels.find((item) => item.id === defaults.levelId);
  return {
    institutionId: ACADEMIC_SCOPE.institution.id,
    institutionName: ACADEMIC_SCOPE.institution.name,
    facultyId: faculty.id,
    facultyName: faculty.name,
    departmentId: department.id,
    departmentName: department.name,
    levelId: level.id,
    levelName: level.name,
    regPrefix: department.regPrefix
  };
}

async function readAcademicCourses() {
  try {
    const rows = await dbAll("SELECT code, title, faculty_id, department_id, level_id, academic_session FROM academic_courses_by_session ORDER BY academic_session DESC, code COLLATE NOCASE");
    return rows.map((row) => ({ code: row.code, title: row.title, facultyId: row.faculty_id, departmentId: row.department_id, levelId: row.level_id, academicSession: row.academic_session || DEFAULT_ACADEMIC_SESSION }));
  } catch {
    return ACADEMIC_SCOPE.courses;
  }
}

function normalizeAcademicSession(value) {
  const match = String(value || "").trim().match(/^(\d{4})\/(\d{4})$/);
  return match && Number(match[2]) === Number(match[1]) + 1 ? match[0] : "";
}

async function getCurrentAcademicSession() {
  const row = await dbGet("SELECT value FROM academic_settings WHERE key = 'current_academic_session'");
  return normalizeAcademicSession(row?.value) || DEFAULT_ACADEMIC_SESSION;
}

async function getAcademicSession(req, res) {
  const currentSession = await getCurrentAcademicSession();
  const startYear = Number(currentSession.slice(0, 4));
  const sessions = Array.from({ length: 6 }, (_, index) => {
    const year = startYear - index;
    return `${year}/${year + 1}`;
  });
  json(res, 200, { ok: true, currentSession, sessions, canChangeCurrent: isOwnerAdmin(getRequestPrincipal(req).admin?.email) });
}

async function setAcademicSession(res, body = {}) {
  const actorEmail = String(body.actorEmail || "").trim().toLowerCase();
  const academicSession = normalizeAcademicSession(body.academicSession);
  if (!isOwnerAdmin(actorEmail)) return json(res, 403, { error: "Only the overall admin can change the current academic session." });
  if (!academicSession) return json(res, 400, { error: "Use an academic session in the format YYYY/YYYY." });
  await dbRun("INSERT INTO academic_settings (key, value, updated_at) VALUES ('current_academic_session', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at", [academicSession, new Date().toISOString()]);
  json(res, 200, { ok: true, currentSession: academicSession });
}

async function getAcademicScope(req, res) {
  let courses = await readAcademicCourses();
  const requestedAcademicSession = normalizeAcademicSession(new URL(req.url, "http://127.0.0.1").searchParams.get("academicSession")) || await getCurrentAcademicSession();
  courses = courses.filter((course) => course.academicSession === requestedAcademicSession);
  const principal = getRequestPrincipal(req);
  if (principal.admin && isLecturerAdmin(principal.admin)) {
    const assignedCodes = new Set(await getLecturerAssignedCourseCodes(principal.admin.email));
    courses = courses.filter((course) => assignedCodes.has(course.code));
  }
  const scope = { ...ACADEMIC_SCOPE, courses };
  json(res, 200, { ok: true, scope, ...scope, academicSession: requestedAcademicSession, defaults: getAcademicDefaults() });
}

function getCourseCode(value) {
  return String(value || "").split(":")[0].trim().toUpperCase();
}

function isLecturerAdmin(admin) {
  return normalizeAdminRole(admin?.adminRole || admin?.role) === "lecturer_admin";
}

async function getLecturerAssignedCourseCodes(email) {
  const lecturerEmail = String(email || "").trim().toLowerCase();
  if (!lecturerEmail) return [];
  const rows = await dbAll("SELECT course_code FROM lecturer_course_assignments WHERE lecturer_email = ? COLLATE NOCASE", [lecturerEmail]);
  return rows.map((row) => String(row.course_code || "").trim().toUpperCase()).filter(Boolean);
}

async function getLecturerAssignments(req, res) {
  const principal = getRequestPrincipal(req);
  if (!principal.admin) return json(res, 403, { error: "Admin access is required." });
  const requestedEmail = String(new URL(req.url, "http://127.0.0.1").searchParams.get("lecturerEmail") || "").trim().toLowerCase();
  if (!isOwnerAdmin(principal.admin.email) && requestedEmail && requestedEmail !== principal.admin.email) return json(res, 403, { error: "You can only view your own course assignments." });
  const lecturerEmail = isOwnerAdmin(principal.admin.email) ? requestedEmail : principal.admin.email;
  const rows = await dbAll("SELECT lecturer_email, course_code, assigned_by, created_at FROM lecturer_course_assignments WHERE (? = '' OR lecturer_email = ? COLLATE NOCASE) ORDER BY lecturer_email COLLATE NOCASE, course_code COLLATE NOCASE", [lecturerEmail, lecturerEmail]);
  const courseMap = new Map((await readAcademicCourses()).map((course) => [course.code, course]));
  const adminMap = new Map(getAdminRoster().map((admin) => [admin.email, admin]));
  json(res, 200, { ok: true, assignments: rows.map((row) => ({ lecturerEmail: row.lecturer_email, lecturerName: adminMap.get(String(row.lecturer_email).toLowerCase())?.fullName || row.lecturer_email, courseCode: row.course_code, courseTitle: courseMap.get(row.course_code)?.title || "", assignedBy: row.assigned_by, createdAt: row.created_at })) });
}

async function saveLecturerCourseAssignment(res, body = {}) {
  const actorEmail = String(body.actorEmail || "").trim().toLowerCase();
  if (!isOwnerAdmin(actorEmail)) return json(res, 403, { error: "Only the overall admin can assign lecturer courses." });
  const lecturer = findAdminByIdentifier(body.lecturerEmail || body.lecturerRegNumber);
  const courseCode = getCourseCode(body.courseCode);
  if (!lecturer || !isLecturerAdmin(lecturer)) return json(res, 400, { error: "Select an admin with the Lecturer Admin role." });
  const course = (await readAcademicCourses()).find((item) => item.code === courseCode);
  if (!course) return json(res, 404, { error: "Course not found." });
  await dbRun("INSERT OR IGNORE INTO lecturer_course_assignments (lecturer_email, course_code, assigned_by, created_at) VALUES (?, ?, ?, ?)", [lecturer.email, courseCode, actorEmail, new Date().toISOString()]);
  json(res, 200, { ok: true, message: `${courseCode} assigned to ${lecturer.fullName || lecturer.email}.` });
}

async function deleteLecturerCourseAssignment(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const actorEmail = String(url.searchParams.get("actorEmail") || "").trim().toLowerCase();
  if (!isOwnerAdmin(actorEmail)) return json(res, 403, { error: "Only the overall admin can remove lecturer course assignments." });
  const lecturerEmail = String(url.searchParams.get("lecturerEmail") || "").trim().toLowerCase();
  const courseCode = getCourseCode(url.searchParams.get("courseCode"));
  await dbRun("DELETE FROM lecturer_course_assignments WHERE lecturer_email = ? COLLATE NOCASE AND course_code = ? COLLATE NOCASE", [lecturerEmail, courseCode]);
  json(res, 200, { ok: true });
}

async function getCourses(req, res) {
  const requested = normalizeAcademicSession(new URL(req.url, "http://127.0.0.1").searchParams.get("academicSession"));
  const current = await getCurrentAcademicSession();
  json(res, 200, { ok: true, courses: (await readAcademicCourses()).filter((course) => course.academicSession === (requested || current)) });
}

async function saveCourse(res, body = {}) {
  const code = String(body.code || "").trim().toUpperCase();
  const title = String(body.title || "").trim();
  const scope = normalizeAcademicScope(body);
  if (!/^[A-Z0-9-]{2,20}$/.test(code)) {
    json(res, 400, { error: "Enter a valid course code." });
    return;
  }
  if (title.length < 3) {
    json(res, 400, { error: "Enter a valid course title." });
    return;
  }
  const academicSession = normalizeAcademicSession(body.academicSession) || await getCurrentAcademicSession();
  await dbRun(`INSERT INTO academic_courses_by_session (code, title, faculty_id, department_id, level_id, academic_session)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(code, academic_session) DO UPDATE SET
      title = excluded.title,
      faculty_id = excluded.faculty_id,
      department_id = excluded.department_id,
      level_id = excluded.level_id,
      academic_session = excluded.academic_session`, [code, title, scope.facultyId, scope.departmentId, scope.levelId, academicSession]);
  const courses = (await readAcademicCourses()).filter((course) => course.academicSession === academicSession);
  json(res, 200, { ok: true, course: { code, title, facultyId: scope.facultyId, departmentId: scope.departmentId, levelId: scope.levelId, academicSession }, courses });
}

async function deleteCourse(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const code = String(url.searchParams.get("code") || "").trim().toUpperCase();
  if (!code) {
    json(res, 400, { error: "Course code is required." });
    return;
  }
  const academicSession = normalizeAcademicSession(url.searchParams.get("academicSession")) || await getCurrentAcademicSession();
  await dbRun("DELETE FROM academic_courses_by_session WHERE code = ? COLLATE NOCASE AND academic_session = ?", [code, academicSession]);
  json(res, 200, { ok: true, courses: (await readAcademicCourses()).filter((course) => course.academicSession === academicSession) });
}

async function initDatabase() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  sqliteDb = await new Promise((resolve, reject) => {
    const db = new sqlite3.Database(SQLITE_DB_FILE, (error) => error ? reject(error) : resolve(db));
  });

  await dbRun("PRAGMA journal_mode = WAL");
  await dbRun("PRAGMA synchronous = NORMAL");
  await dbRun("PRAGMA busy_timeout = 5000");
  await dbRun("PRAGMA foreign_keys = ON");

  await dbRun(`CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    reg_number TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role TEXT NOT NULL DEFAULT 'student',
    verified INTEGER NOT NULL DEFAULT 1,
    signature_data_url TEXT DEFAULT '',
    signature_strokes_json TEXT DEFAULT '[]',
    created_at TEXT,
    updated_at TEXT
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_students_reg_number ON students(reg_number)");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_students_email ON students(email)");
  await ensureColumn("students", "institution_id", "TEXT DEFAULT 'university-of-uyo'");
  await ensureColumn("students", "faculty_id", "TEXT DEFAULT 'engineering'");
  await ensureColumn("students", "faculty_name", "TEXT DEFAULT 'Faculty of Engineering'");
  await ensureColumn("students", "department_id", "TEXT DEFAULT 'electrical-electronics-engineering'");
  await ensureColumn("students", "department_name", "TEXT DEFAULT 'Department of Electrical/Electronics Engineering'");
  await ensureColumn("students", "level_id", "TEXT DEFAULT '100'");
  await ensureColumn("students", "level_name", "TEXT DEFAULT '100 Level'");
  await ensureColumn("students", "password_hash", "TEXT DEFAULT ''");
  await ensureColumn("students", "totp_secret", "TEXT DEFAULT ''");
  await ensureColumn("students", "totp_enabled", "INTEGER NOT NULL DEFAULT 0");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_students_scope ON students(faculty_id, department_id, level_id)");

  await dbRun(`CREATE TABLE IF NOT EXISTS academic_faculties (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS academic_departments (
    id TEXT PRIMARY KEY,
    faculty_id TEXT NOT NULL,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    reg_prefix TEXT NOT NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS academic_levels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS academic_courses (
    code TEXT PRIMARY KEY COLLATE NOCASE,
    title TEXT NOT NULL,
    faculty_id TEXT NOT NULL,
    department_id TEXT NOT NULL,
    level_id TEXT NOT NULL
  )`);
  await ensureColumn("academic_courses", "academic_session", "TEXT DEFAULT ''");
  await dbRun(`CREATE TABLE IF NOT EXISTS academic_courses_by_session (
    code TEXT NOT NULL COLLATE NOCASE,
    academic_session TEXT NOT NULL,
    title TEXT NOT NULL,
    faculty_id TEXT NOT NULL,
    department_id TEXT NOT NULL,
    level_id TEXT NOT NULL,
    PRIMARY KEY (code, academic_session)
  )`);
  await dbRun(`INSERT OR IGNORE INTO academic_courses_by_session (code, academic_session, title, faculty_id, department_id, level_id)
    SELECT code, COALESCE(NULLIF(academic_session, ''), ?), title, faculty_id, department_id, level_id FROM academic_courses`, [DEFAULT_ACADEMIC_SESSION]);
  await dbRun(`CREATE TABLE IF NOT EXISTS academic_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await seedAcademicScope();

  await dbRun(`CREATE TABLE IF NOT EXISTS biometric_profiles (
    profile_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    profile_json TEXT NOT NULL,
    saved_at TEXT NOT NULL
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_biometric_profiles_email ON biometric_profiles(email)");
  await dbRun("CREATE TABLE IF NOT EXISTS webauthn_credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE, credential_id BLOB NOT NULL UNIQUE, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_student ON webauthn_credentials(student_id)");
  await dbRun(`CREATE TABLE IF NOT EXISTS buildings (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    room_note TEXT NOT NULL DEFAULT '',
    geofence_json TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS live_sessions (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    session_json TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    ended_at TEXT
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_live_sessions_status_updated ON live_sessions(status, updated_at)");
  await ensureColumn("live_sessions", "academic_session", "TEXT DEFAULT ''");
  await ensureColumn("live_sessions", "building_id", "TEXT DEFAULT ''");
  await ensureColumn("live_sessions", "session_date", "TEXT DEFAULT ''");

  await dbRun(`CREATE TABLE IF NOT EXISTS attendance (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    email TEXT,
    reg_number TEXT,
    full_name TEXT,
    status TEXT NOT NULL DEFAULT 'present',
    checked_in_at TEXT,
    checked_out_at TEXT,
    saved_at TEXT,
    attendance_json TEXT NOT NULL
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance(session_id)");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_session_reg ON attendance(session_id, reg_number)");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_checked_in ON attendance(checked_in_at)");
  await ensureColumn("attendance", "academic_session", "TEXT DEFAULT ''");
  await ensureColumn("attendance", "checked_out_at", "TEXT");
  await dbRun(`CREATE TABLE IF NOT EXISTS fingerprint_devices (
    esp_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS fingerprint_slots (
    esp_id TEXT NOT NULL,
    slot_id INTEGER NOT NULL,
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    enrolled_at TEXT NOT NULL,
    PRIMARY KEY (esp_id, slot_id),
    UNIQUE (esp_id, student_id)
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS fingerprint_enrollments (
    id TEXT PRIMARY KEY,
    esp_id TEXT NOT NULL,
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    slot_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS device_attendance (
    id TEXT PRIMARY KEY,
    esp_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    attended_at TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'fingerprint',
    UNIQUE(session_id, student_id)
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS student_device_bindings (
    student_id TEXT PRIMARY KEY REFERENCES students(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    bound_at TEXT NOT NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS device_rejected_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    esp_id TEXT NOT NULL,
    session_id TEXT,
    slot_id INTEGER,
    reason TEXT NOT NULL,
    attempted_at TEXT NOT NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS fingerprint_device_commands (
    id TEXT PRIMARY KEY,
    esp_id TEXT NOT NULL,
    command TEXT NOT NULL,
    slot_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await fingerprintCheckin.initialize();
  await dbRun(`CREATE TABLE IF NOT EXISTS attendance_reports (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    academic_session TEXT NOT NULL DEFAULT '',
    report_json TEXT NOT NULL,
    updated_at TEXT
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_reports_academic_session ON attendance_reports(academic_session)");
  await dbRun("UPDATE academic_courses SET academic_session = ? WHERE academic_session IS NULL OR academic_session = ''", [DEFAULT_ACADEMIC_SESSION]);
  await dbRun("UPDATE live_sessions SET academic_session = ? WHERE academic_session IS NULL OR academic_session = ''", [DEFAULT_ACADEMIC_SESSION]);
  await dbRun("UPDATE attendance SET academic_session = ? WHERE academic_session IS NULL OR academic_session = ''", [DEFAULT_ACADEMIC_SESSION]);
  await backfillAcademicSessionJson();
  await dbRun(`CREATE TABLE IF NOT EXISTS lecturer_course_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lecturer_email TEXT NOT NULL COLLATE NOCASE,
    course_code TEXT NOT NULL COLLATE NOCASE,
    assigned_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(lecturer_email, course_code)
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_lecturer_course_assignments_lecturer ON lecturer_course_assignments(lecturer_email)");
  await migrateJsonDataToSqlite();

}

async function migrateJsonDataToSqlite() {
  const students = readJsonFile(STUDENTS_FILE, []);
  for (const student of Array.isArray(students) ? students : []) {
    const normalized = publicStudent(student);
    if (!normalized.email || !normalized.regNumber) continue;
    await upsertSqliteStudent({
    ...normalized,
    passwordHash: student.passwordHash || student.password_hash || "",
    totpSecret: student.totpSecret || student.totp_secret || "",
    totpEnabled: student.totpEnabled || student.totp_enabled || false
  });
  }

  const profiles = readJsonFile(BIOMETRIC_PROFILES_FILE, {});
  for (const profile of Object.values(profiles && typeof profiles === "object" ? profiles : {})) {
    if (!profile?.email) continue;
    const email = String(profile.email || "").trim().toLowerCase();
    const profileId = profile.profileId || crypto.createHash("sha256").update(email).digest("hex");
    const savedAt = profile.savedAt || new Date().toISOString();
    await dbRun(`INSERT OR IGNORE INTO biometric_profiles (profile_id, email, profile_json, saved_at)
      VALUES (?, ?, ?, ?)`, [profileId, email, JSON.stringify({ ...profile, email, profileId, savedAt }), savedAt]);
  }

  const sessions = readJsonFile(LIVE_SESSIONS_FILE, []);
  const normalizedSessions = (Array.isArray(sessions) ? sessions : []).map((session) => ({ ...session, academicSession: normalizeAcademicSession(session?.academicSession) || DEFAULT_ACADEMIC_SESSION }));
  for (const session of normalizedSessions) {
    if (!session?.id) continue;
    await upsertSqliteSession(session);
  }
  if (JSON.stringify(sessions) !== JSON.stringify(normalizedSessions)) writeLocalJson(LIVE_SESSIONS_FILE, normalizedSessions);

  const attendance = readJsonFile(ATTENDANCE_LOG_FILE, []);
  const normalizedAttendance = (Array.isArray(attendance) ? attendance : []).map((record) => ({ ...record, academicSession: normalizeAcademicSession(record?.academicSession) || DEFAULT_ACADEMIC_SESSION }));
  for (const record of normalizedAttendance) {
    if (!record?.id || !record?.sessionId) continue;
    await upsertSqliteAttendance(record);
  }
  if (JSON.stringify(attendance) !== JSON.stringify(normalizedAttendance)) writeLocalJson(ATTENDANCE_LOG_FILE, normalizedAttendance);

  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, []);
  const normalizedReports = (Array.isArray(reports) ? reports : []).map((report) => ({ ...report, academicSession: normalizeAcademicSession(report?.academicSession) || DEFAULT_ACADEMIC_SESSION }));
  for (const normalized of normalizedReports) {
    if (!normalized?.id) continue;
    await dbRun(`INSERT INTO attendance_reports (id, session_id, academic_session, report_json, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET session_id = excluded.session_id, academic_session = excluded.academic_session, report_json = excluded.report_json, updated_at = excluded.updated_at`,
    [normalized.id, normalized.sessionId || "", normalized.academicSession, JSON.stringify(normalized), normalized.updatedAt || normalized.createdAt || new Date().toISOString()]);
  }
}

async function backfillAcademicSessionJson() {
  for (const [table, jsonColumn] of [["live_sessions", "session_json"], ["attendance", "attendance_json"]]) {
    const rows = await dbAll(`SELECT id, ${jsonColumn} FROM ${table}`);
    for (const row of rows) {
      const record = parseJsonColumn(row[jsonColumn], null);
      if (!record || normalizeAcademicSession(record.academicSession)) continue;
      const normalized = { ...record, academicSession: DEFAULT_ACADEMIC_SESSION };
      await dbRun(`UPDATE ${table} SET ${jsonColumn} = ?, academic_session = ? WHERE id = ?`, [JSON.stringify(normalized), DEFAULT_ACADEMIC_SESSION, row.id]);
    }
  }
}

function parseJsonColumn(value, fallback) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function sqliteStudentFromRow(row) {
  if (!row) return null;
  return publicStudent({
    id: row.id,
    fullName: row.full_name,
    regNumber: row.reg_number,
    email: row.email,
    role: row.role,
    verified: row.verified !== 0,
    signatureDataUrl: row.signature_data_url || "",
    signatureStrokes: parseJsonColumn(row.signature_strokes_json, []),
    institutionId: row.institution_id,
    facultyId: row.faculty_id,
    facultyName: row.faculty_name,
    departmentId: row.department_id,
    departmentName: row.department_name,
    levelId: row.level_id,
    levelName: row.level_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    totpEnabled: row.totp_enabled === 1
  });
}

async function upsertSqliteStudent(student) {
  const normalized = publicStudent(student);
  const passwordHash = String(student.passwordHash || student.password_hash || "");
  const totpSecret = String(student.totpSecret || student.totp_secret || "");
  const totpEnabled = student.totpEnabled || student.totp_enabled ? 1 : 0;
  await dbRun(`INSERT INTO students (id, full_name, reg_number, email, role, verified, signature_data_url, signature_strokes_json, institution_id, faculty_id, faculty_name, department_id, department_name, level_id, level_name, password_hash, totp_secret, totp_enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      full_name = excluded.full_name,
      reg_number = excluded.reg_number,
      email = excluded.email,
      role = excluded.role,
      verified = excluded.verified,
      signature_data_url = excluded.signature_data_url,
      signature_strokes_json = excluded.signature_strokes_json,
      institution_id = excluded.institution_id,
      faculty_id = excluded.faculty_id,
      faculty_name = excluded.faculty_name,
      department_id = excluded.department_id,
      department_name = excluded.department_name,
      level_id = excluded.level_id,
      level_name = excluded.level_name,
      password_hash = CASE WHEN excluded.password_hash != '' THEN excluded.password_hash ELSE students.password_hash END,
      totp_secret = CASE WHEN excluded.totp_secret != '' THEN excluded.totp_secret ELSE students.totp_secret END,
      totp_enabled = CASE WHEN excluded.totp_enabled = 1 THEN 1 ELSE students.totp_enabled END,
      created_at = COALESCE(students.created_at, excluded.created_at),
      updated_at = excluded.updated_at`, [
    normalized.id,
    normalized.fullName,
    normalized.regNumber,
    normalized.email,
    normalized.role || "student",
    normalized.verified === false ? 0 : 1,
    normalized.signatureDataUrl || "",
    JSON.stringify(normalized.signatureStrokes || []),
    normalized.institutionId,
    normalized.facultyId,
    normalized.facultyName,
    normalized.departmentId,
    normalized.departmentName,
    normalized.levelId,
    normalized.levelName,
    passwordHash,
    totpSecret,
    totpEnabled,
    normalized.createdAt || new Date().toISOString(),
    normalized.updatedAt || new Date().toISOString()
  ]);
  return normalized;
}
async function readSqliteStudents() {
  const rows = await dbAll("SELECT * FROM students ORDER BY reg_number COLLATE NOCASE ASC");
  return rows.map(sqliteStudentFromRow).filter(Boolean);
}

async function upsertSqliteSession(session) {
  const academicSession = normalizeAcademicSession(session.academicSession) || await getCurrentAcademicSession();
  const normalized = { ...session, academicSession };
  if (session.buildingId) delete normalized.geofence;
  await dbRun(`INSERT INTO live_sessions (id, status, session_json, academic_session, building_id, session_date, created_at, updated_at, ended_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      status = excluded.status,
      session_json = excluded.session_json,
      academic_session = excluded.academic_session,
      building_id = excluded.building_id,
      session_date = excluded.session_date,
      created_at = COALESCE(live_sessions.created_at, excluded.created_at),
      updated_at = excluded.updated_at,
      ended_at = excluded.ended_at`, [
    session.id,
    session.status || "active",
    JSON.stringify(normalized),
    academicSession,
    session.buildingId || "",
    session.date || "",
    session.createdAt || session.created_at || null,
    session.updatedAt || session.updated_at || new Date().toISOString(),
    session.endedAt || session.ended_at || null
  ]);
}

async function readSqliteSessions() {
  const rows = await dbAll("SELECT session_json FROM live_sessions ORDER BY datetime(updated_at) DESC");
  const sessions = rows.map((row) => parseJsonColumn(row.session_json, null)).filter(Boolean);
  const buildingIds = [...new Set(sessions.map((session) => session.buildingId).filter(Boolean))];
  const buildings = new Map();
  for (const id of buildingIds) {
    const row = await dbGet("SELECT id, name, room_note, geofence_json FROM buildings WHERE id = ?", [id]);
    if (row) buildings.set(id, { id: row.id, name: row.name, roomNote: row.room_note, geofence: parseJsonColumn(row.geofence_json, null) });
  }
  return sessions.map((session) => {
    const building = buildings.get(session.buildingId);
    return building ? { ...session, buildingName: building.name, geofence: building.geofence } : session;
  });
}

async function writeSqliteSessions(sessions) {
  for (const session of Array.isArray(sessions) ? sessions : []) {
    if (session?.id) await upsertSqliteSession(session);
  }
  writeLocalJson(LIVE_SESSIONS_FILE, (Array.isArray(sessions) ? sessions : []).map((session) => {
    if (!session?.buildingId) return session;
    const { geofence, ...stored } = session;
    return stored;
  }));
}

async function upsertSqliteAttendance(record) {
  const academicSession = normalizeAcademicSession(record.academicSession) || await getCurrentAcademicSession();
  const normalized = { ...record, academicSession };
  await dbRun(`INSERT INTO attendance (id, session_id, email, reg_number, full_name, status, checked_in_at, checked_out_at, saved_at, academic_session, student_id, match_score, ip, "timestamp", attendance_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      session_id = excluded.session_id,
      email = excluded.email,
      reg_number = excluded.reg_number,
      full_name = excluded.full_name,
      status = excluded.status,
      checked_in_at = excluded.checked_in_at,
      checked_out_at = excluded.checked_out_at,
      saved_at = excluded.saved_at,
      academic_session = excluded.academic_session,
      student_id = excluded.student_id,
      match_score = excluded.match_score,
      ip = excluded.ip,
      "timestamp" = excluded."timestamp",
      attendance_json = excluded.attendance_json`, [
    record.id,
    record.sessionId,
    record.email || "",
    record.regNumber || "",
    record.fullName || "",
    record.status || "present",
    record.checkedInAt || null,
    record.checkedOutAt || null,
    record.savedAt || new Date().toISOString(),
    academicSession,
    record.studentId || null,
    Number.isFinite(Number(record.matchScore)) ? Number(record.matchScore) : null,
    record.ip || null,
    record.timestamp || record.checkedInAt || null,
    JSON.stringify(normalized)
  ]);
}

async function readSqliteAttendance() {
  const rows = await dbAll("SELECT attendance_json FROM attendance ORDER BY datetime(checked_in_at) DESC");
  return rows.map((row) => parseJsonColumn(row.attendance_json, null)).filter(Boolean).map((record) => ({
    ...record,
    status: ["fingerprint", "phone-token"].includes(record.method) || record.manuallyEditedAt || record.status === "absent" ? record.status : record.checkedOutAt ? record.status : "incomplete"
  }));
}

async function writeSqliteAttendance(attendance) {
  for (const record of Array.isArray(attendance) ? attendance : []) {
    if (record?.id && record?.sessionId) await upsertSqliteAttendance(record);
  }
  writeLocalJson(ATTENDANCE_LOG_FILE, attendance);
}
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value) {
  const clean = String(value || "").toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let current = 0;
  const bytes = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) continue;
    current = (current << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpKeyUri(email, issuer, secret) {
  const label = `${issuer}:${email}`;
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function generateTotpCode(secret, stepOffset = 0) {
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 30000) + stepOffset;
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, "0");
}

function verifyTotpCode(code, secret) {
  const token = String(code || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(token) || !secret) return false;
  return [-1, 0, 1].some((offset) => {
    const expected = generateTotpCode(secret, offset);
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  });
}
async function setupRegistrationTotp(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const fullName = String(body.fullName || email || "GeoAttend Student").trim();
  if (!isEmail(email)) {
    json(res, 400, { error: "Enter a valid email address." });
    return;
  }
  const secret = generateTotpSecret();
  const service = "GeoAttend";
  const otpauth = totpKeyUri(email, service, secret);
  const qrDataUrl = await QRCode.toDataURL(otpauth, { margin: 1, width: 240 });
  totpSetupStore.set(email, {
    secret,
    fullName,
    createdAt: Date.now(),
    expiresAt: Date.now() + 15 * 60 * 1000
  });
  json(res, 200, {
    ok: true,
    message: "Google Authenticator setup created.",
    qrDataUrl,
    manualKey: secret,
    issuer: service,
    account: email
  });
}

function verifyRegistrationTotp(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || body.otp || "").replace(/\s+/g, "");
  const setup = totpSetupStore.get(email);
  if (!setup || setup.expiresAt < Date.now()) {
    totpSetupStore.delete(email);
    json(res, 400, { error: "Authenticator setup expired. Generate a new QR code." });
    return;
  }
  const ok = verifyTotpCode(code, setup.secret);
  if (!ok) {
    json(res, 400, { error: "Incorrect authenticator code. Check Google Authenticator and try again." });
    return;
  }
  totpSetupStore.delete(email);
  json(res, 200, {
    ok: true,
    message: "Authenticator verified.",
    totpSecret: setup.secret,
    totpEnabled: true
  });
}
async function sendOtp(res, email, purpose, fullName = "") {
  if (!isEmail(email)) {
    json(res, 400, { error: "Enter a valid email address." });
    return;
  }

  const key = `${purpose}:${String(email).trim().toLowerCase()}`;
  if (isRateLimited(otpAttemptStore, key, 5, 10 * 60 * 1000)) {
    json(res, 429, { error: "Too many OTP requests. Try again in a few minutes." });
    return;
  }

  const otp = crypto.randomInt(100000, 1000000).toString();
  otpStore.set(otpKey(email, purpose), {
    otp,
    expiresAt: Date.now() + OTP_TTL_MS
  });

  const message = {
    to: email.trim().toLowerCase(),
    subject: purpose === "reset" ? "Your GeoAttend password reset code" : "Your GeoAttend verification code",
    text: `Hi${fullName ? ` ${fullName}` : ""},\n\nYour GeoAttend ${purpose === "reset" ? "password reset" : "account verification"} code is ${otp}.\n\nThis code expires in 10 minutes. If you did not request it, you can ignore this email.\n\nGeoAttend`,
    html: `
      <div style="font-family:Inter,Arial,sans-serif;line-height:1.5;color:#0b1c30">
        <h2>Your GeoAttend verification code</h2>
        <p>${fullName ? `Hi ${escapeHtml(fullName)},` : "Hi,"}</p>
        <p>Your ${purpose === "reset" ? "password reset" : "account verification"} code is:</p>
        <p style="font-size:28px;font-weight:800;letter-spacing:6px;color:#0058be">${otp}</p>
        <p>This code expires in 10 minutes.</p>
        <p style="color:#45464d;font-size:13px">If you did not request this code, you can ignore this email.</p>
      </div>
    `
  };

  const smtpConfigured = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "MAIL_FROM", "SMTP_FROM"].some((key) => Boolean(process.env[key]));
  const payload = {
    ok: true,
    message: smtpConfigured ? "OTP created. Email is sending now." : "OTP created in demo mode. Use the code shown in the response to continue.",
    resendAfterSeconds: OTP_RESEND_COOLDOWN_SECONDS,
    demoOtp: smtpConfigured ? undefined : otp,
    deliveryMode: smtpConfigured ? "email" : "demo"
  };

  json(res, 200, payload);

  setImmediate(() => {
    if (!smtpConfigured) {
      appendLog(SERVER_OUT_LOG, `OTP demo mode for ${maskEmail(email)} | purpose=${purpose} | code=${otp}`);
      return;
    }

    sendEmailWithRetry(message).then((info) => {
      appendLog(SERVER_OUT_LOG, `OTP email accepted for ${maskEmail(email)} | purpose=${purpose} | accepted=${JSON.stringify(info.accepted || [])} | rejected=${JSON.stringify(info.rejected || [])} | messageId=${info.messageId || "none"}`);
    }).catch((error) => {
      appendLog(SERVER_ERR_LOG, `OTP email failed for ${maskEmail(email)} | purpose=${purpose} | ${error.code || "ERROR"} ${error.message}`);
    });
  });
}

async function sendPasswordResetOtp(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  if (!isEmail(email)) {
    json(res, 400, { error: "Enter a valid email address." });
    return;
  }
  const row = await dbGet("SELECT full_name FROM students WHERE email = ? COLLATE NOCASE LIMIT 1", [email]);
  if (!row) {
    json(res, 404, { error: "No student account was found for that email." });
    return;
  }
  await sendOtp(res, email, "reset", row.full_name || "");
}
async function verifyPasswordResetOtp(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const otp = String(body.otp || "").trim();
  const password = String(body.password || "");
  const saved = otpStore.get(otpKey(email, "reset"));
  if (!saved || saved.expiresAt < Date.now()) {
    otpStore.delete(otpKey(email, "reset"));
    json(res, 400, { error: "OTP expired or was not requested. Please request a new code." });
    return;
  }
  if (otp !== saved.otp) {
    json(res, 400, { error: "Incorrect OTP. Please check the code and try again." });
    return;
  }
  otpStore.delete(otpKey(email, "reset"));
  if (!password) {
    json(res, 200, { ok: true, message: "OTP verified." });
    return;
  }
  if (password.length < 8) {
    json(res, 400, { error: "New password must be at least 8 characters." });
    return;
  }
  const result = await dbRun("UPDATE students SET password_hash = ?, updated_at = ? WHERE email = ? COLLATE NOCASE", [hashPassword(password), new Date().toISOString(), email]);
  if (!result.changes) {
    json(res, 404, { error: "No student account was found for that email." });
    return;
  }
  json(res, 200, { ok: true, message: "Password updated." });
}
async function verifyPasswordResetTotp(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || body.otp || "").replace(/\s+/g, "");
  const password = String(body.password || "");
  if (!isEmail(email)) {
    json(res, 400, { error: "Enter a valid email address." });
    return;
  }
  const row = await dbGet("SELECT * FROM students WHERE email = ? COLLATE NOCASE LIMIT 1", [email]);
  if (!row) {
    json(res, 404, { error: "No student account was found for that email." });
    return;
  }
  const secret = String(row.totp_secret || "");
  if (!secret || row.totp_enabled !== 1) {
    json(res, 409, { error: "Google Authenticator is not set up for this account. Register again or contact admin." });
    return;
  }
  if (!verifyTotpCode(code, secret)) {
    json(res, 400, { error: "Incorrect Google Authenticator code." });
    return;
  }
  if (!password) {
    json(res, 200, { ok: true, verified: true, message: "Authenticator code verified." });
    return;
  }
  if (password.length < 8) {
    json(res, 400, { error: "New password must be at least 8 characters." });
    return;
  }
  await dbRun("UPDATE students SET password_hash = ?, updated_at = ? WHERE email = ? COLLATE NOCASE", [hashPassword(password), new Date().toISOString(), email]);
  json(res, 200, { ok: true, verified: true, message: "Password updated." });
}
function verifyOtp(res, email, otp, purpose) {
  const saved = otpStore.get(otpKey(email, purpose));
  if (!saved || saved.expiresAt < Date.now()) {
    json(res, 400, { error: "OTP expired or was not requested. Please request a new code." });
    return;
  }

  if (String(otp || "").trim() !== saved.otp) {
    json(res, 400, { error: "Incorrect OTP. Please check the code and try again." });
    return;
  }

  otpStore.delete(otpKey(email, purpose));
  json(res, 200, { ok: true });
}

function shouldRetryEmail(error) {
  const code = String(error?.code || "");
  const message = String(error?.message || "").toLowerCase();
  return ["ETIMEDOUT", "ECONNECTION", "ECONNRESET", "EPIPE"].includes(code)
    || message.includes("timeout")
    || message.includes("temporarily");
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendEmailWithRetry(message, retries = 2) {
  let lastError = null;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await sendEmail(message);
    } catch (error) {
      lastError = error;
      mailTransporter = null;
      if (attempt >= retries || !shouldRetryEmail(error)) break;
      await wait(1200 * (attempt + 1));
    }
  }
  throw lastError;
}

async function sendEmail(message) {
  const mailFrom = process.env.MAIL_FROM || process.env.SMTP_FROM;
  const required = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS"];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length || !mailFrom) {
    console.warn(`SMTP not fully configured; falling back to demo OTP mode. Missing: ${missing.join(", ") || "sender address"}.`);
    return {
      accepted: [{ address: message.to }],
      rejected: [],
      messageId: `demo-${Date.now()}`
    };
  }

  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
      pool: true,
      maxConnections: 2,
      maxMessages: 100,
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 10000,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  return mailTransporter.sendMail({
    from: mailFrom,
    sender: process.env.SMTP_USER,
    replyTo: process.env.SMTP_USER,
    envelope: {
      from: process.env.SMTP_USER,
      to: message.to
    },
    priority: "high",
    headers: {
      "X-Auto-Response-Suppress": "All",
      "X-Entity-Ref-ID": crypto.randomUUID(),
      "List-Unsubscribe": "<mailto:" + process.env.SMTP_USER + ">",
      "X-Priority": "3"
    },
    ...message
  });
}

function appendLog(filePath, message) {
  const line = `[${new Date().toISOString()}] ${message}\n`;
  fs.appendFile(filePath, line, () => {});
}

function requireDeviceAdmin(req, res) {
  const auth = String(req.headers.authorization || "");
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const admin = verifyAdminApiToken(token);
  if (!admin || normalizeAdminRole(admin.adminRole || admin.role) !== "overall_admin") {
    json(res, 401, { error: "Sign in again as Overall Admin to manage fingerprint devices." });
    return null;
  }
  return admin;
}

function createAdminApiToken(admin) {
  const now = Math.floor(Date.now() / 1000);
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const unsigned = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ sub: admin.email, role: normalizeAdminRole(admin.adminRole || admin.role), iat: now, exp: now + 8 * 60 * 60 })}`;
  const signature = crypto.createHmac("sha256", ADMIN_JWT_SECRET).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
}

function verifyAdminApiToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", ADMIN_JWT_SECRET).update(unsigned).digest("base64url");
  if (!timingSafeTextEqual(expected, parts[2])) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!claims.sub || !Number.isFinite(claims.exp) || claims.exp <= Date.now() / 1000) return null;
    const admin = findAdminByIdentifier(claims.sub);
    return admin && normalizeAdminRole(admin.adminRole || admin.role) === claims.role ? admin : null;
  } catch { return null; }
}

function timingSafeTextEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

async function authenticateFingerprintDevice(req, espId) {
  const device = await dbGet("SELECT esp_id, api_key_hash FROM fingerprint_devices WHERE esp_id = ? AND enabled = 1", [espId]);
  if (!device) return null;
  const supplied = String(req.headers["x-device-key"] || "");
  const suppliedHash = crypto.createHash("sha256").update(supplied).digest("hex");
  return timingSafeTextEqual(suppliedHash, device.api_key_hash) ? device : null;
}

function sessionWindow(session) {
  const date = String(session?.date || "");
  const startTime = String(session?.attendanceStart || session?.checkInStartTime || session?.startTime || "00:00");
  const endTime = String(session?.attendanceEnd || session?.checkInEndTime || session?.endTime || "23:59");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{2}:\d{2}$/.test(startTime) || !/^\d{2}:\d{2}$/.test(endTime)) return null;
  const toUtc = (time) => {
    const [year, month, day] = date.split("-").map(Number);
    const [hour, minute] = time.split(":").map(Number);
    return Date.UTC(year, month - 1, day, hour - 1, minute);
  };
  return { start: toUtc(startTime), end: toUtc(endTime) };
}

async function handleFingerprintDeviceApi(req, res, body) {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname === "/api/devices" && req.method === "GET") {
    if (!requireDeviceAdmin(req, res, body)) return;
    const devices = await dbAll("SELECT esp_id AS espId, name, enabled, created_at AS createdAt FROM fingerprint_devices ORDER BY name COLLATE NOCASE");
    json(res, 200, { ok: true, devices }); return;
  }
  if (req.url === "/api/devices" && req.method === "POST") {
    if (!requireDeviceAdmin(req, res, body)) return;
    const espId = String(body.espId || "").trim();
    const name = String(body.name || espId).trim().slice(0, 80);
    if (!/^[A-Za-z0-9_-]{3,64}$/.test(espId) || !name) { json(res, 400, { error: "Enter a device ID (3–64 letters, numbers, _ or -) and name." }); return; }
    const apiKey = crypto.randomBytes(32).toString("base64url");
    const apiKeyHash = crypto.createHash("sha256").update(apiKey).digest("hex");
    await dbRun("INSERT INTO fingerprint_devices (esp_id, name, api_key_hash, enabled, created_at) VALUES (?, ?, ?, 1, ?) ON CONFLICT(esp_id) DO UPDATE SET name = excluded.name, api_key_hash = excluded.api_key_hash, enabled = 1", [espId, name, apiKeyHash, new Date().toISOString()]);
    json(res, 201, { ok: true, device: { espId, name }, apiKey }); return;
  }
  if (req.url === "/api/devices/disable" && req.method === "POST") {
    if (!requireDeviceAdmin(req, res, body)) return;
    await dbRun("UPDATE fingerprint_devices SET enabled = 0 WHERE esp_id = ?", [String(body.espId || "")]);
    json(res, 200, { ok: true }); return;
  }
  if (url.pathname === "/api/devices/enrollments" && req.method === "GET") {
    if (!requireDeviceAdmin(req, res, body)) return;
    const espId = url.searchParams.get("espId") || "";
    const slots = await dbAll("SELECT f.esp_id AS espId, f.slot_id AS slotId, s.id AS studentId, s.full_name AS name, s.reg_number AS matricNo, f.enrolled_at AS enrolledAt FROM fingerprint_slots f JOIN students s ON s.id = f.student_id WHERE (? = '' OR f.esp_id = ?) ORDER BY f.esp_id, f.slot_id", [espId, espId]);
    const enrollments = await dbAll("SELECT e.id, e.esp_id AS espId, e.slot_id AS slotId, s.full_name AS name, s.reg_number AS matricNo, e.status, e.created_at AS createdAt FROM fingerprint_enrollments e JOIN students s ON s.id = e.student_id WHERE e.status = 'pending' AND (? = '' OR e.esp_id = ?) ORDER BY e.created_at", [espId, espId]);
    json(res, 200, { ok: true, slots, enrollments }); return;
  }
  if (req.url === "/api/devices/enrollment-request" && req.method === "POST") {
    if (!requireDeviceAdmin(req, res, body)) return;
    const espId = String(body.espId || "").trim();
    const studentId = String(body.studentId || "").trim();
    if (!await dbGet("SELECT esp_id FROM fingerprint_devices WHERE esp_id = ? AND enabled = 1", [espId])) { json(res, 404, { error: "Enabled ESP device not found." }); return; }
    if (!await dbGet("SELECT id FROM students WHERE id = ?", [studentId])) { json(res, 404, { error: "Student not found." }); return; }
    if (await dbGet("SELECT slot_id FROM fingerprint_slots WHERE esp_id = ? AND student_id = ?", [espId, studentId])) { json(res, 409, { error: "This student already has a fingerprint slot on that device." }); return; }
    if (await dbGet("SELECT id FROM fingerprint_enrollments WHERE esp_id = ? AND student_id = ? AND status = 'pending'", [espId, studentId])) { json(res, 409, { error: "An enrollment request is already pending." }); return; }
    const occupied = new Set((await dbAll("SELECT slot_id AS slotId FROM fingerprint_slots WHERE esp_id = ? UNION SELECT slot_id AS slotId FROM fingerprint_enrollments WHERE esp_id = ? AND status = 'pending' UNION SELECT slot_id AS slotId FROM fingerprint_device_commands WHERE esp_id = ? AND status = 'pending'", [espId, espId, espId])).map((item) => Number(item.slotId)));
    let slotId = 0;
    for (let candidate = 1; candidate <= 127; candidate += 1) if (!occupied.has(candidate)) { slotId = candidate; break; }
    if (!slotId) { json(res, 409, { error: "The device has reached its configured 127-slot capacity." }); return; }
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    await dbRun("INSERT INTO fingerprint_enrollments (id, esp_id, student_id, slot_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)", [id, espId, studentId, slotId, now, now]);
    json(res, 201, { ok: true, enrollment: { id, espId, slotId, status: "pending" } }); return;
  }
  if (req.url === "/api/devices/biometric-delete" && req.method === "POST") {
    if (!requireDeviceAdmin(req, res, body)) return;
    const studentId = String(body.studentId || "");
    if (!await dbGet("SELECT id FROM students WHERE id = ?", [studentId])) { json(res, 404, { error: "Student not found." }); return; }
    const assigned = await dbAll("SELECT esp_id, slot_id FROM fingerprint_slots WHERE student_id = ?", [studentId]);
    const now = new Date().toISOString();
    for (const item of assigned) await dbRun("INSERT INTO fingerprint_device_commands (id, esp_id, command, slot_id, status, created_at, updated_at) VALUES (?, ?, 'delete-slot', ?, 'pending', ?, ?)", [crypto.randomUUID(), item.esp_id, item.slot_id, now, now]);
    await dbRun("DELETE FROM fingerprint_slots WHERE student_id = ?", [studentId]);
    await dbRun("DELETE FROM fingerprint_enrollments WHERE student_id = ?", [studentId]);
    await dbRun("DELETE FROM biometric_profiles WHERE email = (SELECT email FROM students WHERE id = ?)", [studentId]);
    await dbRun("DELETE FROM webauthn_credentials WHERE student_id = ?", [studentId]);
    json(res, 200, { ok: true, pendingSensorDeletes: assigned.length, message: "Server-side fingerprint mapping, stored biometric profile, and passkey credentials deleted. The sensor will clear enrolled templates the next time it connects." }); return;
  }
  if (url.pathname === "/api/device/session" && req.method === "GET") {
    const espId = url.searchParams.get("espId") || "";
    if (!await authenticateFingerprintDevice(req, espId)) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const { items } = await readLiveSessionsStore();
    const dateParts = new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Lagos", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date());
    const today = `${dateParts.find((part) => part.type === "year")?.value}-${dateParts.find((part) => part.type === "month")?.value}-${dateParts.find((part) => part.type === "day")?.value}`;
    const active = items.filter((session) => session.status === "active" && (session.date || "") === today);
    const session = active.sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")))[0] || null;
    json(res, 200, { ok: true, session: session ? { id: session.id, course: session.course, date: session.date, startTime: session.startTime, endTime: session.endTime, attendanceStart: session.attendanceStart || session.checkInStartTime, attendanceEnd: session.attendanceEnd || session.checkInEndTime } : null, serverTime: new Date().toISOString() }); return;
  }
  if (url.pathname === "/api/device/enrollment" && req.method === "GET") {
    const espId = url.searchParams.get("espId") || "";
    if (!await authenticateFingerprintDevice(req, espId)) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const enrollment = await dbGet(`SELECT e.id, e.slot_id AS slotId, s.id AS studentId, s.full_name AS name, s.reg_number AS matricNo
      FROM fingerprint_enrollments e JOIN students s ON s.id = e.student_id
      WHERE e.esp_id = ? AND e.status = 'pending' ORDER BY e.created_at LIMIT 1`, [espId]);
    json(res, 200, { ok: true, enrollment: enrollment || null }); return;
  }
  if (url.pathname === "/api/device/commands" && req.method === "GET") {
    const espId = url.searchParams.get("espId") || "";
    if (!await authenticateFingerprintDevice(req, espId)) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const command = await dbGet("SELECT id, command, slot_id AS slotId FROM fingerprint_device_commands WHERE esp_id = ? AND status = 'pending' ORDER BY created_at LIMIT 1", [espId]);
    json(res, 200, { ok: true, command: command || null }); return;
  }
  if (url.pathname === "/api/device/commands/result" && req.method === "POST") {
    const espId = String(body.espId || "");
    if (!await authenticateFingerprintDevice(req, espId)) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const now = new Date().toISOString();
    const result = await dbRun("UPDATE fingerprint_device_commands SET status = ?, updated_at = ? WHERE id = ? AND esp_id = ? AND status = 'pending'", [body.ok === true ? "complete" : "failed", now, String(body.commandId || ""), espId]);
    json(res, result.changes ? 200 : 404, { ok: Boolean(result.changes) }); return;
  }
  if (url.pathname === "/api/device/enrollment/result" && req.method === "POST") {
    const espId = String(body.espId || "");
    if (!await authenticateFingerprintDevice(req, espId)) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const enrollment = await dbGet("SELECT * FROM fingerprint_enrollments WHERE id = ? AND esp_id = ? AND status = 'pending'", [String(body.enrollmentId || ""), espId]);
    if (!enrollment) { json(res, 404, { error: "Enrollment request was not found or has expired." }); return; }
    if (body.ok === true) {
      await dbRun("INSERT INTO fingerprint_slots (esp_id, slot_id, student_id, enrolled_at) VALUES (?, ?, ?, ?) ON CONFLICT(esp_id, slot_id) DO UPDATE SET student_id = excluded.student_id, enrolled_at = excluded.enrolled_at", [espId, enrollment.slot_id, enrollment.student_id, new Date().toISOString()]);
      await dbRun("UPDATE fingerprint_enrollments SET status = 'complete', updated_at = ? WHERE id = ?", [new Date().toISOString(), enrollment.id]);
      json(res, 200, { ok: true, status: "complete" });
    } else {
      await dbRun("UPDATE fingerprint_enrollments SET status = 'failed', updated_at = ? WHERE id = ?", [new Date().toISOString(), enrollment.id]);
      json(res, 200, { ok: true, status: "failed" });
    }
    return;
  }
  if (url.pathname === "/api/device/checkin" && req.method === "POST") {
    const espId = String(body.espId || "");
    const device = await authenticateFingerprintDevice(req, espId);
    if (!device) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const attemptedAt = new Date().toISOString();
    const sessionId = String(body.sessionId || "");
    const slotId = Number(body.slotId);
    const fail = async (status, reason) => {
      await dbRun("INSERT INTO device_rejected_attempts (esp_id, session_id, slot_id, reason, attempted_at) VALUES (?, ?, ?, ?, ?)", [espId, sessionId, Number.isInteger(slotId) ? slotId : null, reason.slice(0, 160), attemptedAt]);
      json(res, status, { ok: false, status: "rejected", reason });
    };
    const timestamp = new Date(body.timestamp || attemptedAt);
    if (!Number.isInteger(slotId) || slotId < 1 || slotId > 127 || Number.isNaN(timestamp.getTime()) || timestamp.getTime() > Date.now() + 5 * 60 * 1000 || timestamp.getTime() < Date.now() - 48 * 60 * 60 * 1000) { await fail(400, "Invalid slot or timestamp."); return; }
    const sessionRows = await readLiveSessionsStore();
    const session = sessionRows.items.find((item) => item.id === sessionId);
    const window = sessionWindow(session);
    if (!session || !["active", "ended"].includes(session.status) || !window || timestamp.getTime() < window.start || timestamp.getTime() > window.end) { await fail(403, "No valid attendance session window."); return; }
    const slot = await dbGet("SELECT s.id, s.full_name, s.reg_number, s.email, s.department_id, s.department_name, s.faculty_id, s.faculty_name, s.level_id, s.level_name FROM fingerprint_slots f JOIN students s ON s.id = f.student_id WHERE f.esp_id = ? AND f.slot_id = ?", [espId, slotId]);
    if (!slot) { await fail(404, "Fingerprint slot is not registered to a student."); return; }
    if (await dbGet("SELECT id FROM attendance WHERE session_id = ? AND student_id = ?", [sessionId, slot.id])) { json(res, 200, { ok: true, status: "duplicate", student: { name: slot.full_name, matricNo: slot.reg_number } }); return; }
    const rowId = crypto.randomUUID();
    const insert = await dbRun("INSERT OR IGNORE INTO device_attendance (id, esp_id, session_id, student_id, attended_at, method) VALUES (?, ?, ?, ?, ?, 'fingerprint')", [rowId, espId, sessionId, slot.id, timestamp.toISOString()]);
    if (!insert.changes) { json(res, 200, { ok: true, status: "duplicate", student: { name: slot.full_name, matricNo: slot.reg_number } }); return; }
    const record = { id: rowId, sessionId, course: session.course || "Lecture", studentId: slot.id, email: slot.email, fullName: slot.full_name, regNumber: slot.reg_number, departmentId: slot.department_id, departmentName: slot.department_name, facultyId: slot.faculty_id, facultyName: slot.faculty_name, levelId: slot.level_id, levelName: slot.level_name, status: "present", method: "fingerprint", verificationMethod: "Fingerprint sensor", deviceId: espId, checkedInAt: timestamp.toISOString(), savedAt: attemptedAt, academicSession: session.academicSession || DEFAULT_ACADEMIC_SESSION };
    try {
      const attendance = (await readAttendanceStore()).items;
      await writeAttendanceStore([record, ...attendance]);
    } catch (error) {
      await dbRun("DELETE FROM device_attendance WHERE id = ?", [rowId]);
      throw error;
    }
    json(res, 201, { ok: true, status: "accepted", student: { name: slot.full_name, matricNo: slot.reg_number }, attendanceId: rowId }); return;
  }
  if (url.pathname === "/api/device/phone-checkin" && req.method === "POST") {
    const espId = String(body.espId || "");
    if (!await authenticateFingerprintDevice(req, espId)) { json(res, 401, { error: "Invalid or disabled device credentials." }); return; }
    const email = String(body.email || "").trim().toLowerCase();
    const student = await dbGet("SELECT s.* FROM students s JOIN student_device_bindings b ON b.student_id = s.id WHERE s.email = ? COLLATE NOCASE AND b.device_id = ?", [email, String(body.deviceId || "")]);
    const suppliedSlot = Number(body.timeSlot);
    const secret = String(process.env.DEVICE_TOKEN_SECRET || "");
    const sessionId = String(body.sessionId || "");
    const message = `${sessionId}|${suppliedSlot}`;
    const expected = secret ? crypto.createHmac("sha256", secret).update(message).digest("hex").slice(0, 8) : "";
    const currentSlot = Math.floor(Date.now() / 30000);
    if (!student || !secret || !timingSafeTextEqual(expected, String(body.token || "").toLowerCase()) || ![currentSlot, currentSlot - 1].includes(suppliedSlot)) {
      await dbRun("INSERT INTO device_rejected_attempts (esp_id, session_id, slot_id, reason, attempted_at) VALUES (?, ?, NULL, ?, ?)", [espId, sessionId, "Invalid phone token or unbound phone.", new Date().toISOString()]);
      json(res, 401, { ok: false, status: "rejected", reason: "Invalid token or phone is not bound to this student." }); return;
    }
    const session = (await readLiveSessionsStore()).items.find((item) => item.id === sessionId && item.status === "active");
    const window = sessionWindow(session);
    const timestamp = new Date();
    if (!window || timestamp.getTime() < window.start || timestamp.getTime() > window.end) {
      await dbRun("INSERT INTO device_rejected_attempts (esp_id, session_id, slot_id, reason, attempted_at) VALUES (?, ?, NULL, ?, ?)", [espId, sessionId, "Phone scan outside session window.", timestamp.toISOString()]);
      json(res, 403, { ok: false, status: "rejected", reason: "No valid attendance session window." }); return;
    }
    if (await dbGet("SELECT id FROM attendance WHERE session_id = ? AND student_id = ?", [sessionId, student.id])) { json(res, 200, { ok: true, status: "duplicate", student: { name: student.full_name, matricNo: student.reg_number } }); return; }
    const rowId = crypto.randomUUID();
    const inserted = await dbRun("INSERT OR IGNORE INTO device_attendance (id, esp_id, session_id, student_id, attended_at, method) VALUES (?, ?, ?, ?, ?, 'phone')", [rowId, espId, sessionId, student.id, timestamp.toISOString()]);
    if (!inserted.changes) { json(res, 200, { ok: true, status: "duplicate", student: { name: student.full_name, matricNo: student.reg_number } }); return; }
    const record = { id: rowId, sessionId, course: session.course || "Lecture", studentId: student.id, email: student.email, fullName: student.full_name, regNumber: student.reg_number, departmentId: student.department_id, departmentName: student.department_name, facultyId: student.faculty_id, facultyName: student.faculty_name, levelId: student.level_id, levelName: student.level_name, status: "present", method: "phone-token", verificationMethod: "Phone via attendance Wi-Fi", deviceId: espId, checkedInAt: timestamp.toISOString(), savedAt: timestamp.toISOString(), academicSession: session.academicSession || DEFAULT_ACADEMIC_SESSION };
    try { const attendance = (await readAttendanceStore()).items; await writeAttendanceStore([record, ...attendance]); }
    catch (error) { await dbRun("DELETE FROM device_attendance WHERE id = ?", [rowId]); throw error; }
    json(res, 201, { ok: true, status: "accepted", student: { name: student.full_name, matricNo: student.reg_number } }); return;
  }
  json(res, 404, { error: "Fingerprint device endpoint not found." });
}

async function bindStudentDevice(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const deviceId = String(body.deviceId || "").trim();
  if (!email || password.length < 1 || !/^[A-Za-z0-9_-]{8,100}$/.test(deviceId)) { json(res, 400, { error: "Enter your account login and a phone device ID (8–100 letters/numbers)." }); return; }
  const key = `bind-device:${email}`;
  if (isRateLimited(loginAttemptStore, key, 5, 10 * 60 * 1000)) { json(res, 429, { error: "Too many attempts. Try again later." }); return; }
  const row = await dbGet("SELECT * FROM students WHERE email = ? COLLATE NOCASE LIMIT 1", [email]);
  if (!row || !row.password_hash || !verifyStoredPassword(password, { passwordHash: row.password_hash })) { json(res, 401, { error: "Account login was not accepted." }); return; }
  await dbRun("INSERT INTO student_device_bindings (student_id, device_id, bound_at) VALUES (?, ?, ?) ON CONFLICT(student_id) DO UPDATE SET device_id = excluded.device_id, bound_at = excluded.bound_at", [row.id, deviceId, new Date().toISOString()]);
  json(res, 200, { ok: true, message: "This phone is now bound to your student account." });
}

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host}`).pathname);
  const safePath = path.normalize(urlPath === "/" ? "/login.html" : urlPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(ROOT, safePath);

  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, getCorsHeaders());
    res.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404, getCorsHeaders());
      res.end("Not found");
      return;
    }

    const contentType = mimeTypes[path.extname(filePath).toLowerCase()] || "application/octet-stream";
    res.writeHead(200, {
      ...getCorsHeaders(),
      "Content-Type": contentType,
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      "Pragma": "no-cache",
      "Expires": "0"
    });
    res.end(data);
  });
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 16e6) {
        req.destroy();
        reject(new Error("Request body too large."));
      }
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new Error("Invalid JSON."));
      }
    });
  });
}

function json(res, status, payload) {
  res.writeHead(status, {
    ...getCorsHeaders(),
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    "Pragma": "no-cache",
    "Expires": "0"
  });
  res.end(JSON.stringify(payload));
}

function getCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Key"
  };
}

function setCorsHeaders(res) {
  Object.entries(getCorsHeaders()).forEach(([key, value]) => res.setHeader(key, value));
}

function getWebAuthnContext(req) {
  // WebAuthn must use the public HTTPS hostname seen by the browser.
  const forwardedProtocol = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const protocol = forwardedProtocol === "https" || req.socket?.encrypted ? "https" : "http";
  const forwardedHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const forwardedHostname = forwardedHost.replace(/^\[|\]$/g, "").split(":")[0].toLowerCase();
  const publicForwardedHost = protocol === "https" && forwardedHost && forwardedHostname !== "localhost" && forwardedHostname !== "127.0.0.1";
  const originHeader = String(req.headers.origin || "").trim();
  if (originHeader) {
    const origin = new URL(originHeader);
    const local = origin.hostname === "localhost" || origin.hostname === "127.0.0.1";
    if (origin.protocol !== "https:" && !local) throw new Error("WebAuthn requires the exact HTTPS page address.");
    if (publicForwardedHost && local) return { rpName: "GeoAttend", rpID: forwardedHostname, origin: "https://" + forwardedHost };
    return { rpName: "GeoAttend", rpID: origin.hostname, origin: origin.origin };
  }
  const host = publicForwardedHost ? forwardedHost : String(req.headers.host || ("127.0.0.1:" + PORT)).split(",")[0].trim();
  const hostname = host.replace(/^\[|\]$/g, "").split(":")[0];
  if (protocol !== "https" && hostname !== "localhost") throw new Error("WebAuthn requires an HTTPS origin. Open the exact HTTPS tunnel address.");
  return { rpName: "GeoAttend", rpID: hostname, origin: protocol + "://" + host };
}
function getWebAuthnContextDiagnostic(req) {
  let context = null;
  let error = null;
  try { context = getWebAuthnContext(req); } catch (value) { error = value.message; }
  return { host: String(req.headers.host || ""), originHeader: String(req.headers.origin || ""), forwardedHost: String(req.headers["x-forwarded-host"] || ""), forwardedProtocol: String(req.headers["x-forwarded-proto"] || ""), rpID: context?.rpID || null, origin: context?.origin || null, error };
}

function webAuthnKey(purpose, email) {
  return purpose + ":" + String(email || "").trim().toLowerCase();
}

async function findWebAuthnStudent(identifier) {
  const value = String(identifier || "").trim();
  return dbGet("SELECT * FROM students WHERE email = ? COLLATE NOCASE OR reg_number = ? COLLATE NOCASE LIMIT 1", [value.toLowerCase(), normalizeRegNumber(value)]);
}

function encodeCredential(credential) {
  return { id: credential.id, publicKey: Buffer.from(credential.publicKey).toString("base64url"), counter: Number(credential.counter || 0) };
}

async function getWebAuthnRegistrationOptions(req, res, body) {
  const row = await findWebAuthnStudent(body.email || body.regNumber);
  if (!row) return json(res, 404, { error: "Complete student registration first." });
  const email = String(row.email).trim().toLowerCase();
  const context = getWebAuthnContext(req);
  const existing = await dbAll("SELECT credential_id FROM webauthn_credentials WHERE student_id = ?", [row.id]);
  const options = await generateRegistrationOptions({
    rpName: context.rpName,
    rpID: context.rpID,
    userName: email,
    userDisplayName: row.full_name || email,
    userID: Buffer.from(String(row.id)),
    attestationType: "none",
    excludeCredentials: existing.map((item) => ({ id: Buffer.from(item.credential_id).toString("base64url") })),
    authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" }
  });
  webAuthnChallengeStore.set(webAuthnKey("register", email), { challenge: options.challenge, rpID: context.rpID, origin: context.origin, expiresAt: Date.now() + 5 * 60 * 1000 });
  json(res, 200, { ok: true, options, email });
}

async function verifyWebAuthnRegistration(req, res, body) {
  const row = await findWebAuthnStudent(body.email || body.regNumber);
  if (!row) return json(res, 404, { error: "Student account was not found." });
  const email = String(row.email).trim().toLowerCase();
  const key = webAuthnKey("register", email);
  const saved = webAuthnChallengeStore.get(key);
  if (!saved || saved.expiresAt < Date.now()) return json(res, 400, { error: "Device enrollment expired. Try again." });
  try {
    const verification = await verifyRegistrationResponse({ response: body.response, expectedChallenge: saved.challenge, expectedOrigin: saved.origin, expectedRPID: saved.rpID, requireUserVerification: true });
    if (!verification.verified || !verification.registrationInfo?.credential) return json(res, 401, { error: "Device enrollment was not verified." });
    const credential = verification.registrationInfo.credential;
    await dbRun("INSERT INTO webauthn_credentials (student_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?) ON CONFLICT(credential_id) DO UPDATE SET public_key = excluded.public_key, sign_count = excluded.sign_count", [row.id, Buffer.from(credential.id, "base64url"), Buffer.from(credential.publicKey), Number(credential.counter || 0)]);
    webAuthnChallengeStore.delete(key);
    json(res, 200, { ok: true, email, credential: encodeCredential(credential) });
  } catch (error) {
    json(res, 400, { error: error.message || "Device enrollment failed." });
  }
}

async function getWebAuthnStatus(res, identifier) {
  const row = await findWebAuthnStudent(identifier);
  if (!row) return json(res, 200, { ok: true, enabled: false });
  const credential = await dbGet("SELECT id FROM webauthn_credentials WHERE student_id = ? LIMIT 1", [row.id]);
  json(res, 200, { ok: true, enabled: Boolean(credential), email: row.email });
}

async function removeWebAuthnCredential(res, body) {
  const row = await findWebAuthnStudent(body.email || body.regNumber);
  if (!row) return json(res, 404, { error: "Student account was not found." });
  await dbRun("DELETE FROM webauthn_credentials WHERE student_id = ?", [row.id]);
  json(res, 200, { ok: true, enabled: false });
}

async function getWebAuthnLoginOptions(req, res, body) {
  const context = getWebAuthnContext(req);
  const conditional = body.mediation === "conditional";
  const row = conditional ? null : await findWebAuthnStudent(body.email || body.regNumber);
  if (!conditional && !row) return json(res, 404, { error: "Student account was not found." });
  const credentials = row ? await dbAll("SELECT credential_id FROM webauthn_credentials WHERE student_id = ?", [row.id]) : [];
  if (!conditional && !credentials.length) return json(res, 409, { error: "Fingerprint enrollment is required. Complete registration first." });
  const options = await generateAuthenticationOptions({
    rpID: context.rpID,
    userVerification: "required",
    allowCredentials: conditional ? [] : credentials.map((item) => ({ id: Buffer.from(item.credential_id).toString("base64url"), type: "public-key" }))
  });
  const challengeId = crypto.randomBytes(24).toString("base64url");
  webAuthnChallengeStore.set(webAuthnKey("login-challenge", challengeId), { challenge: options.challenge, rpID: context.rpID, origin: context.origin, purpose: body.purpose === "attendance" ? "attendance" : "login", action: body.action === "check-out" ? "check-out" : "check-in", sessionId: String(body.sessionId || ""), expiresAt: Date.now() + 5 * 60 * 1000 });
  json(res, 200, { ok: true, options, challengeId, email: row ? String(row.email).trim().toLowerCase() : undefined });
}

async function verifyWebAuthnLogin(req, res, body) {
  const challengeId = String(body.challengeId || "");
  const key = webAuthnKey("login-challenge", challengeId);
  const saved = challengeId ? webAuthnChallengeStore.get(key) : null;
  if (!saved || saved.expiresAt < Date.now()) return json(res, 400, { error: "Fingerprint request expired. Try again." });
  const rawId = String(body.response?.rawId || "");
  const stored = rawId ? await dbGet("SELECT * FROM webauthn_credentials WHERE credential_id = ?", [Buffer.from(rawId, "base64url")]) : null;
  if (!stored) return json(res, 401, { error: "This passkey is not enrolled." });
  const row = await dbGet("SELECT * FROM students WHERE id = ?", [stored.student_id]);
  if (!row) return json(res, 404, { error: "Student account was not found." });
  const email = String(row.email).trim().toLowerCase();
  try {
    const verification = await verifyAuthenticationResponse({ response: body.response, expectedChallenge: saved.challenge, expectedOrigin: saved.origin, expectedRPID: saved.rpID, requireUserVerification: true, credential: { id: Buffer.from(stored.credential_id).toString("base64url"), publicKey: Buffer.from(stored.public_key), counter: Number(stored.sign_count || 0) } });
    if (!verification.verified) return json(res, 401, { error: "Fingerprint verification failed." });
    const newCounter = Number(verification.authenticationInfo?.newCounter || 0);
    const oldCounter = Number(stored.sign_count || 0);
    if (oldCounter > 0 && newCounter <= oldCounter) return json(res, 401, { error: "Fingerprint security counter failed. Re-enroll this device." });
    await dbRun("UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?", [newCounter, stored.id]);
    webAuthnChallengeStore.delete(key);
    let checkinToken = null;
    if (saved.purpose === "attendance" && saved.sessionId) {
      checkinToken = crypto.randomBytes(32).toString("base64url");
      attendanceAuthorizationStore.set(checkinToken, { email, sessionId: saved.sessionId, action: saved.action || "check-in", expiresAt: Date.now() + 2 * 60 * 1000 });
    }
    json(res, 200, { ok: true, user: sqliteStudentFromRow(row), method: "fingerprint", checkinToken });
  } catch (error) {
    json(res, 400, { error: error.message || "Fingerprint verification failed." });
  }
}
async function saveBiometricProfile(res, profile) {
  if (!profile || !isEmail(profile.email)) {
    json(res, 400, { error: "A valid profile email is required." });
    return;
  }

  const hasSecurity = Boolean(profile?.faceTemplateHash || profile?.faceCaptures);
  if (!hasSecurity) {
    json(res, 400, { error: "Complete one login security method before saving." });
    return;
  }

  const email = profile.email.trim().toLowerCase();
  const normalizedProfile = {
    ...profile,
    email,

  };
  const { profileId, savedAt } = await saveBiometricProfileObject(normalizedProfile);
  json(res, 200, { ok: true, source: "sqlite", profileId, savedAt });
}

async function getBiometricProfile(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const email = String(url.searchParams.get("email") || "").trim().toLowerCase();

  if (!isEmail(email)) {
    json(res, 400, { error: "A valid email is required." });
    return;
  }

  const profileId = crypto.createHash("sha256").update(email).digest("hex");
  const row = await dbGet("SELECT profile_json FROM biometric_profiles WHERE profile_id = ? OR email = ?", [profileId, email]);
  const profile = parseJsonColumn(row?.profile_json, null);

  if (!profile) {
    json(res, 404, { error: "No biometric profile found for that email." });
    return;
  }

  json(res, 200, { ok: true, source: "sqlite", profile });
}

async function getLiveSessions(req, res) {
  await autoFinalizeExpiredSessions();
  const { items: sessions, source } = await readLiveSessionsStore();
  const activeSessions = sessions
    .filter((session) => session && session.status === "active")
    .sort((a, b) => new Date(b.createdAt || b.updatedAt || 0) - new Date(a.createdAt || a.updatedAt || 0));
  const requestedSession = normalizeAcademicSession(new URL(req.url, "http://127.0.0.1").searchParams.get("academicSession")) || await getCurrentAcademicSession();
  const visibleSessions = (await filterSessionsForRequest(req, activeSessions)).filter((session) => (session.academicSession || DEFAULT_ACADEMIC_SESSION) === requestedSession);

  json(res, 200, {
    ok: true,
    source,
    sessions: visibleSessions,
    activeSession: visibleSessions[0] || null
  });
}

function validateSessionGeofence(geofence) {
  if (String(geofence?.type || "circle").toLowerCase() === "polygon") {
    const coordinates = geofence?.coordinates;
    if (!Array.isArray(coordinates) || coordinates.length < 3 || coordinates.some((point) => !Array.isArray(point) || point.length !== 2 || !point.every(Number.isFinite) || Math.abs(point[0]) > 90 || Math.abs(point[1]) > 180)) {
      return { ok: false, error: "A polygon geofence needs at least three valid [latitude, longitude] points." };
    }
    const normalized = { type: "polygon", coordinates: coordinates.map(([lat, lng]) => [Number(lat), Number(lng)]) };
    if (geofence.shape === "rectangle" || geofence.shape === "square") {
      const lat = Number(geofence.lat), lng = Number(geofence.lng);
      const lengthMeters = Number(geofence.lengthMeters ?? geofence.sideMeters), breadthMeters = Number(geofence.breadthMeters ?? geofence.sideMeters);
      if (![lat, lng, lengthMeters, breadthMeters].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lng) > 180 || lengthMeters < MIN_GEOFENCE_RADIUS_METERS || lengthMeters > MAX_GEOFENCE_RADIUS_METERS || breadthMeters < MIN_GEOFENCE_RADIUS_METERS || breadthMeters > MAX_GEOFENCE_RADIUS_METERS) return { ok: false, error: "A rectangle needs a valid center and length and breadth from 20m to 5,000m." };
      Object.assign(normalized, { shape: geofence.shape, lat, lng, lengthMeters, breadthMeters });
    }
    return { ok: true, geofence: normalized };
  }
  const lat = Number(geofence?.lat);
  const lng = Number(geofence?.lng);
  const radius = Number(geofence?.radius);
  if (![lat, lng, radius].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
    return { ok: false, error: "This session does not have a valid building boundary." };
  }
  if (radius < MIN_GEOFENCE_RADIUS_METERS || radius > MAX_GEOFENCE_RADIUS_METERS) {
    return { ok: false, error: `Session radius must be between ${MIN_GEOFENCE_RADIUS_METERS}m and ${MAX_GEOFENCE_RADIUS_METERS}m.` };
  }
  return { ok: true, geofence: { type: "circle", lat, lng, radius } };
}

async function getBuildings(req, res) {
  const rows = await dbAll("SELECT id, name, room_note, geofence_json, created_at, updated_at FROM buildings ORDER BY name COLLATE NOCASE");
  json(res, 200, { ok: true, buildings: rows.map((row) => ({ id: row.id, name: row.name, roomNote: row.room_note, geofence: parseJsonColumn(row.geofence_json, null), createdAt: row.created_at, updatedAt: row.updated_at })) });
}

async function saveBuilding(res, body) {
  const actorAdmin = findAdminByIdentifier(body.actorEmail || "");
  if (!actorAdmin || !["overall_admin", "building_admin"].includes(normalizeAdminRole(actorAdmin.adminRole || actorAdmin.role))) return json(res, 403, { error: "Building management requires Overall Admin or Building Admin access." });
  const name = String(body.name || "").trim();
  if (!name) return json(res, 400, { error: "Building name is required." });
  const validation = validateSessionGeofence(body.geofence);
  if (!validation.ok) return json(res, 400, { error: validation.error });
  const id = String(body.id || crypto.randomUUID());
  const now = new Date().toISOString();
  try {
    await dbRun(`INSERT INTO buildings (id, name, room_note, geofence_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET name = excluded.name, room_note = excluded.room_note, geofence_json = excluded.geofence_json, updated_at = excluded.updated_at`,
    [id, name, String(body.roomNote || "").trim(), JSON.stringify(validation.geofence), body.createdAt || now, now]);
  } catch (error) {
    if (String(error.message || "").includes("UNIQUE")) return json(res, 409, { error: "A building with that name already exists." });
    throw error;
  }
  const building = { id, name, roomNote: String(body.roomNote || "").trim(), geofence: validation.geofence, updatedAt: now };
  json(res, 200, { ok: true, building });
}

async function deleteBuilding(res, body) {
  const actorAdmin = findAdminByIdentifier(body.actorEmail || "");
  if (!actorAdmin || !["overall_admin", "building_admin"].includes(normalizeAdminRole(actorAdmin.adminRole || actorAdmin.role))) return json(res, 403, { error: "Building management requires Overall Admin or Building Admin access." });
  const id = String(body.id || "").trim();
  if (!id) return json(res, 400, { error: "Building id is required." });
  const upcoming = await dbGet("SELECT id FROM live_sessions WHERE building_id = ? AND session_date >= date('now', 'localtime') AND status NOT IN ('ended', 'cancelled') LIMIT 1", [id]);
  if (upcoming) return json(res, 409, { error: "This building has upcoming sessions. Cancel or move them before deleting it." });
  await dbRun("DELETE FROM buildings WHERE id = ?", [id]);
  json(res, 200, { ok: true });
}

async function saveLiveSession(res, session) {
  if (!session || typeof session !== "object") {
    json(res, 400, { error: "A valid session payload is required." });
    return;
  }

  const id = String(session.id || "").trim();
  if (!id) {
    json(res, 400, { error: "A session id is required." });
    return;
  }

  const buildingId = String(session.buildingId || "").trim();
  const buildingRow = buildingId ? await dbGet("SELECT id, name, room_note, geofence_json FROM buildings WHERE id = ?", [buildingId]) : null;
  if (!buildingRow) { json(res, 400, { error: "Select a saved building before creating the session." }); return; }
  const geofenceCheck = validateSessionGeofence(parseJsonColumn(buildingRow.geofence_json, null));
  if (!geofenceCheck.ok) { json(res, 400, { error: "The selected building geofence is invalid." }); return; }

  const actorAdmin = findAdminByIdentifier(session.actorEmail || session.createdBy || "");
  if (!actorAdmin) { json(res, 403, { error: "Admin access is required to create or edit sessions." }); return; }
  const minimumDurationPercent = Number(session.minimumDurationPercent || 0);
  if (!Number.isFinite(minimumDurationPercent) || minimumDurationPercent < 0 || minimumDurationPercent > 100) {
    json(res, 400, { error: "Minimum duration must be between 0 and 100 percent." }); return;
  }
  for (const field of ["attendanceStart", "attendanceEnd", "startTime", "endTime", "sessionEndTime", "checkInStartTime", "checkInEndTime", "checkOutStartTime", "checkOutEndTime"]) {
    if (session[field] && !/^\d{2}:\d{2}$/.test(String(session[field]))) { json(res, 400, { error: `Invalid session time: ${field}.` }); return; }
  }
  const sessionDate = String(session.date || "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(sessionDate) || Number.isNaN(new Date(`${sessionDate}T00:00:00`).getTime())) {
    json(res, 400, { error: "Choose a valid class date." }); return;
  }
  const recurrenceEndDate = String(session.recurrenceEndDate || "");
  const recurrenceDays = Array.isArray(session.recurrenceDays) ? [...new Set(session.recurrenceDays.map(Number).filter((day) => Number.isInteger(day) && day >= 0 && day <= 6))] : [];
  if (recurrenceDays.length && (!/^\d{4}-\d{2}-\d{2}$/.test(recurrenceEndDate) || recurrenceEndDate < sessionDate || (new Date(`${recurrenceEndDate}T00:00:00`) - new Date(`${sessionDate}T00:00:00`)) > 366 * 86400000)) {
    json(res, 400, { error: "Choose a recurrence end date within one year of the first class date." }); return;
  }

  const { items: sessions } = await readLiveSessionsStore();
  const editing = sessions.find((item) => item?.id === id);
  if (editing && !entityMatchesScope(editing, actorAdmin, actorAdmin.adminRole || actorAdmin.role)) {
    json(res, 403, { error: "This session is outside your admin scope." }); return;
  }
  const seriesId = editing?.seriesId || id;
  const scopedSession = { ...applyAdminScopeToSession(session, actorAdmin), academicSession: await getCurrentAcademicSession() };
  if (actorAdmin && isLecturerAdmin(actorAdmin)) {
    const assignedCodes = await getLecturerAssignedCourseCodes(actorAdmin.email);
    if (!assignedCodes.includes(getCourseCode(scopedSession.course))) {
      json(res, 403, { error: "You can only create sessions for courses assigned to your Lecturer Admin account." });
      return;
    }
  }
  const now = new Date().toISOString();
  const occurrenceDates = [];
  if (recurrenceDays.length) {
    for (const date = new Date(`${sessionDate}T12:00:00`); date <= new Date(`${recurrenceEndDate}T23:59:59`); date.setDate(date.getDate() + 1)) {
      if (recurrenceDays.includes(date.getDay())) occurrenceDates.push(date.toISOString().slice(0, 10));
    }
  } else occurrenceDates.push(sessionDate);
  if (!occurrenceDates.length) { json(res, 400, { error: "The selected recurrence days are outside the date range." }); return; }
  const generated = occurrenceDates.map((date) => ({
    ...scopedSession,
    id: date === sessionDate ? id : `${seriesId}-${date.replaceAll("-", "")}`,
    seriesId: recurrenceDays.length ? seriesId : "",
    buildingId, buildingName: buildingRow.name, roomNote: String(session.roomNote || "").trim(), date,
    recurrenceDays, recurrenceEndDate: recurrenceDays.length ? recurrenceEndDate : "",
    minimumDurationPercent, status: "active", geofence: geofenceCheck.geofence,
    createdAt: editing?.createdAt || now, updatedAt: now
  }));
  const generatedIds = new Set(generated.map((item) => item.id));
  const replacementIds = new Set(sessions.filter((item) => item?.id === seriesId || item?.seriesId === seriesId).map((item) => item.id));
  const obsoleteFutureOccurrences = sessions.filter((item) => item && replacementIds.has(item.id) && !generatedIds.has(item.id) && item.date >= sessionDate && item.status === "active");
  const replacementSessions = sessions.filter((item) => item && replacementIds.has(item.id) && !generatedIds.has(item.id) && !obsoleteFutureOccurrences.some((obsolete) => obsolete.id === item.id));
  const nextSessions = [...generated, ...replacementSessions, ...sessions.filter((item) => item && !generatedIds.has(item.id) && !replacementIds.has(item.id)), ...obsoleteFutureOccurrences.map((item) => ({ ...item, status: "cancelled", cancelledAt: now, updatedAt: now }))];
  const { source } = await writeLiveSessionsStore(nextSessions);

  json(res, 200, { ok: true, source, session: generated[0], sessions: nextSessions.filter((item) => item.status === "active") });
}

async function cancelLiveSession(res, body) {
  const admin = findAdminByIdentifier(body.actorEmail || "");
  if (!admin) return json(res, 403, { error: "Admin access is required to cancel sessions." });
  const id = String(body.sessionId || "").trim();
  const { items: sessions } = await readLiveSessionsStore();
  const session = sessions.find((item) => item?.id === id);
  if (!session) return json(res, 404, { error: "Session not found." });
  if (!entityMatchesScope(session, admin, admin.adminRole || admin.role)) return json(res, 403, { error: "This session is outside your admin scope." });
  const cancelledAt = new Date().toISOString();
  const cancelledIds = new Set([id, ...sessions.filter((item) => item?.seriesId && item.seriesId === (session.seriesId || id)).map((item) => item.id)]);
  const next = sessions.map((item) => item && cancelledIds.has(item.id) && item.status === "active" ? { ...item, status: "cancelled", cancelledAt, updatedAt: cancelledAt } : item);
  await writeLiveSessionsStore(next);
  json(res, 200, { ok: true, sessions: next.filter((item) => item?.status === "active") });
}

async function endLiveSession(res, sessionId) {
  const id = String(sessionId || "").trim();
  if (!id) {
    json(res, 400, { error: "A session id is required." });
    return;
  }

  const { items: sessions } = await readLiveSessionsStore();
  const endedAt = new Date().toISOString();
  const endedSession = sessions.find((session) => session && session.id === id) || null;
  const nextSessions = sessions.map((session) => (
    session && session.id === id ? { ...session, status: "ended", endedAt, updatedAt: endedAt } : session
  ));

  const { source } = await writeLiveSessionsStore(nextSessions);
  if (endedSession) {
    await ensureAbsentAttendance(endedSession);
    saveAttendanceReportFile({ ...endedSession, status: "ended", endedAt, updatedAt: endedAt }, "manual-end");
  }
  json(res, 200, { ok: true, source, sessions: nextSessions.filter((session) => session && session.status === "active") });
}

async function getAttendance(req, res) {
  await autoFinalizeExpiredSessions();
  const url = new URL(req.url, "http://127.0.0.1");
  const sessionId = String(url.searchParams.get("sessionId") || "").trim();
  const { items, source } = await readAttendanceStore();
  const principal = getRequestPrincipal(req);
  const lecturerCourseCodes = principal.admin && isLecturerAdmin(principal.admin)
    ? new Set(await getLecturerAssignedCourseCodes(principal.admin.email))
    : null;
  const requestedAcademicSession = normalizeAcademicSession(url.searchParams.get("academicSession")) || await getCurrentAcademicSession();
  const attendance = items
    .filter((entry) => entry && (!sessionId || entry.sessionId === sessionId))
    .filter((entry) => (entry.academicSession || DEFAULT_ACADEMIC_SESSION) === requestedAcademicSession)
    .filter((entry) => {
      if (lecturerCourseCodes) return lecturerCourseCodes.has(getCourseCode(entry.course));
      if (principal.admin) return entityMatchesScope(entry, principal.admin, principal.admin.adminRole || principal.admin.role);
      if (principal.studentEmail) return String(entry.email || "").trim().toLowerCase() === principal.studentEmail;
      return true;
    })
    .sort((a, b) => new Date(b.checkedInAt || 0) - new Date(a.checkedInAt || 0));

  json(res, 200, { ok: true, source, attendance });
}

function getAttendancePdfPayload(sessionId, academicSession = "") {
  const sessions = readJsonFile(LIVE_SESSIONS_FILE, []);
  const session = sessions.find((item) => item && item.id === sessionId) || null;
  const attendance = readJsonFile(ATTENDANCE_LOG_FILE, [])
    .filter((entry) => entry && (!sessionId || entry.sessionId === sessionId))
    .filter((entry) => !academicSession || (entry.academicSession || DEFAULT_ACADEMIC_SESSION) === academicSession)
    .map((entry) => ({ ...entry, status: ["fingerprint", "phone-token"].includes(entry.method) || entry.manuallyEditedAt || entry.status === "absent" ? entry.status : entry.checkedOutAt ? entry.status : "incomplete" }))
    .sort((a, b) => new Date(a.checkedInAt || 0) - new Date(b.checkedInAt || 0));
  const title = session?.course || attendance[0]?.course || (sessionId ? "Session Attendance Report" : "Attendance Report");
  const fileSafeTitle = title.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "attendance-report";
  const pdf = createAttendancePdf({ title, session: { ...session, academicSession: academicSession || session?.academicSession || DEFAULT_ACADEMIC_SESSION }, sessionId, attendance });

  return {
    attendance,
    filename: `${fileSafeTitle}.pdf`,
    pdf,
    session,
    sessionId,
    title
  };
}

function serveAttendancePdf(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const sessionId = String(url.searchParams.get("sessionId") || "").trim();
  const academicSession = normalizeAcademicSession(url.searchParams.get("academicSession"));
  const { pdf, filename } = getAttendancePdfPayload(sessionId, academicSession);

  res.writeHead(200, {
    ...getCorsHeaders(),
    "Content-Type": "application/pdf",
    "Content-Disposition": `attachment; filename="${filename}"`,
    "Content-Length": pdf.length
  });
  res.end(pdf);
}

async function getAttendanceReports(req, res) {
  await autoFinalizeExpiredSessions();
  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, [])
    .filter((report) => report && report.id && report.filename)
    .sort((a, b) => new Date(b.createdAt || b.updatedAt || 0) - new Date(a.createdAt || a.updatedAt || 0));
  const requestedAcademicSession = normalizeAcademicSession(new URL(req.url, "http://127.0.0.1").searchParams.get("academicSession")) || await getCurrentAcademicSession();
  const visibleReports = (await filterReportsForRequest(req, reports)).filter((report) => (report.academicSession || DEFAULT_ACADEMIC_SESSION) === requestedAcademicSession);
  json(res, 200, { ok: true, reports: visibleReports.map(publicAttendanceReport) });
}

function serveSavedAttendanceReport(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const reportId = String(url.searchParams.get("id") || "").trim();
  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, []);
  const report = reports.find((item) => item && item.id === reportId);
  if (!report) {
    json(res, 404, { error: "Saved PDF report was not found." });
    return;
  }

  const filePath = path.join(ATTENDANCE_REPORTS_DIR, report.filename);
  if (!filePath.startsWith(ATTENDANCE_REPORTS_DIR)) {
    json(res, 400, { error: "Invalid saved PDF path." });
    return;
  }
  if (!fs.existsSync(filePath)) {
    writeSavedReportPdf(report);
  }
  if (!fs.existsSync(filePath)) {
    json(res, 404, { error: "Saved PDF file was not found." });
    return;
  }

  const pdf = fs.readFileSync(filePath);
  res.writeHead(200, {
    ...getCorsHeaders(),
    "Content-Type": "application/pdf",
    "Content-Disposition": `attachment; filename="${report.filename}"`,
    "Content-Length": pdf.length
  });
  res.end(pdf);
}

function addManualAttendanceReportName(res, body) {
  const reportId = String(body.reportId || "").trim();
  const fullName = String(body.fullName || "").trim();
  const regNumber = String(body.regNumber || "").trim();
  if (!reportId || !fullName) {
    json(res, 400, { error: "Report and full name are required." });
    return;
  }

  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, []);
  const report = reports.find((item) => item && item.id === reportId);
  if (!report) {
    json(res, 404, { error: "Saved PDF report was not found." });
    return;
  }

  const manualRecord = {
    id: `manual-${Date.now()}`,
    fullName,
    regNumber: regNumber || "--",
    verificationMethod: "Manual",
    checkedInAt: new Date().toISOString(),
    status: "present",
    course: report.title || "Live class",
    sessionId: report.sessionId || ""
  };

  const updatedReport = {
    ...report,
    manualRecords: [...(Array.isArray(report.manualRecords) ? report.manualRecords : []), manualRecord],
    updatedAt: new Date().toISOString()
  };
  writeSavedReportPdf(updatedReport);
  writeAttendanceReports(reports.map((item) => item.id === reportId ? updatedReport : item));
  json(res, 200, { ok: true, report: publicAttendanceReport(updatedReport) });
}

function deleteAttendanceReport(res, body) {
  const reportId = String(body.reportId || "").trim();
  if (!reportId) {
    json(res, 400, { error: "Report id is required." });
    return;
  }

  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, []);
  const report = reports.find((item) => item && item.id === reportId);
  if (!report) {
    json(res, 404, { error: "Saved PDF report was not found." });
    return;
  }

  const filePath = path.join(ATTENDANCE_REPORTS_DIR, report.filename);
  if (filePath.startsWith(ATTENDANCE_REPORTS_DIR) && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
  writeAttendanceReports(reports.filter((item) => item && item.id !== reportId));
  json(res, 200, { ok: true });
}

async function autoFinalizeExpiredSessions() {
  const { items: sessions } = await readLiveSessionsStore();
  const now = new Date();
  const ended = [];
  const nextSessions = sessions.map((session) => {
    if (!session || session.status !== "active") return session;
    const endDate = getSessionEndDate(session);
    if (!endDate || endDate > now) return session;
    const endedSession = {
      ...session,
      status: "ended",
      endedAt: endDate.toISOString(),
      updatedAt: now.toISOString()
    };
    ended.push(endedSession);
    return endedSession;
  });

  if (ended.length) {
    await writeLiveSessionsStore(nextSessions);
    for (const session of ended) {
      await ensureAbsentAttendance(session);
      saveAttendanceReportFile(session, "auto-end");
    }
  }
}

async function ensureAbsentAttendance(session) {
  const [students, { items: attendance }] = await Promise.all([readStudentsStore(), readAttendanceStore()]);
  const enrolled = students.filter((student) => student && student.role !== "admin"
    && (!session.departmentId || student.departmentId === session.departmentId)
    && (!session.levelId || student.levelId === session.levelId));
  const known = new Set(attendance.filter((item) => item.sessionId === session.id).map((item) => String(item.email || "").toLowerCase()));
  const missing = enrolled.filter((student) => !known.has(String(student.email || "").toLowerCase())).map((student) => ({
    id: crypto.createHash("sha256").update(`${session.id}:${student.email || student.regNumber}`).digest("hex"),
    sessionId: session.id, academicSession: session.academicSession || DEFAULT_ACADEMIC_SESSION,
    course: session.course, email: student.email, fullName: student.fullName, regNumber: student.regNumber,
    departmentId: student.departmentId, facultyId: student.facultyId, levelId: student.levelId,
    status: "absent", checkedInAt: null, checkedOutAt: null, durationMinutes: null, savedAt: new Date().toISOString()
  }));
  if (missing.length) await writeAttendanceStore([...attendance, ...missing]);
}

function saveAttendanceReportFile(session, reason = "generated") {
  if (!session?.id) return null;
  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, []);
  const existing = reports.find((report) => report && report.sessionId === session.id);
  const payload = getAttendancePdfPayload(session.id);
  const now = new Date().toISOString();
  const report = {
    ...(existing || {}),
    id: existing?.id || `report-${session.id}`,
    attendanceCount: payload.attendance.length + (existing?.manualRecords?.length || 0),
    createdAt: existing?.createdAt || now,
    filename: existing?.filename || getSavedReportFilename(payload.title, session.id),
    manualRecords: Array.isArray(existing?.manualRecords) ? existing.manualRecords : [],
    reason,
    institutionId: session.institutionId || payload.session?.institutionId || existing?.institutionId || "",
    facultyId: session.facultyId || payload.session?.facultyId || existing?.facultyId || "",
    facultyName: session.facultyName || payload.session?.facultyName || existing?.facultyName || "",
    departmentId: session.departmentId || payload.session?.departmentId || existing?.departmentId || "",
    departmentName: session.departmentName || payload.session?.departmentName || existing?.departmentName || "",
    levelId: session.levelId || payload.session?.levelId || existing?.levelId || "",
    levelName: session.levelName || payload.session?.levelName || existing?.levelName || "",
    academicSession: session.academicSession || existing?.academicSession || DEFAULT_ACADEMIC_SESSION,
    sessionId: session.id,
    title: payload.title,
    updatedAt: now
  };
  writeSavedReportPdf(report, payload);
  dbRun(`INSERT INTO attendance_reports (id, session_id, academic_session, report_json, updated_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET session_id = excluded.session_id, academic_session = excluded.academic_session, report_json = excluded.report_json, updated_at = excluded.updated_at`,
  [report.id, report.sessionId, report.academicSession, JSON.stringify(report), report.updatedAt]).catch(() => {});
  const nextReports = [report, ...reports.filter((item) => item && item.id !== report.id)].slice(0, 200);
  writeAttendanceReports(nextReports);
  return report;
}

function writeSavedReportPdf(report, payload = null) {
  const data = payload || getAttendancePdfPayload(report.sessionId || "");
  const attendance = [
    ...data.attendance,
    ...(Array.isArray(report.manualRecords) ? report.manualRecords : [])
  ].sort((a, b) => new Date(a.checkedInAt || 0) - new Date(b.checkedInAt || 0));
  const pdf = createAttendancePdf({
    title: report.title || data.title,
    session: { ...data.session, academicSession: report.academicSession || data.session?.academicSession || DEFAULT_ACADEMIC_SESSION },
    sessionId: report.sessionId || data.sessionId,
    attendance
  });

  fs.mkdirSync(ATTENDANCE_REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(ATTENDANCE_REPORTS_DIR, report.filename), pdf);
}

function writeAttendanceReports(reports) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(ATTENDANCE_REPORTS_DIR, { recursive: true });
  fs.writeFileSync(ATTENDANCE_REPORTS_INDEX_FILE, JSON.stringify(reports, null, 2));
}

function publicAttendanceReport(report) {
  return {
    attendanceCount: report.attendanceCount || 0,
    createdAt: report.createdAt,
    filename: report.filename,
    id: report.id,
    manualCount: Array.isArray(report.manualRecords) ? report.manualRecords.length : 0,
    sessionId: report.sessionId,
    academicSession: report.academicSession || DEFAULT_ACADEMIC_SESSION,
    institutionId: report.institutionId || "",
    facultyId: report.facultyId || "",
    facultyName: report.facultyName || "",
    departmentId: report.departmentId || "",
    departmentName: report.departmentName || "",
    levelId: report.levelId || "",
    levelName: report.levelName || "",
    title: report.title,
    updatedAt: report.updatedAt,
    url: `/api/attendance-report-file?id=${encodeURIComponent(report.id)}`
  };
}

function getSavedReportFilename(title, sessionId) {
  const safeTitle = String(title || "attendance-report")
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase() || "attendance-report";
  const safeSession = String(sessionId || Date.now()).replace(/[^a-z0-9-]+/gi, "-").toLowerCase();
  return `${safeTitle}-${safeSession}.pdf`;
}

async function sendAttendancePdf(res, body) {
  const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  if (!isEmail(adminEmail)) {
    json(res, 500, { error: "Admin email is not configured. Add ADMIN_EMAIL to .env." });
    return;
  }

  const sessionId = String(body.sessionId || "").trim();
  const sessions = readJsonFile(LIVE_SESSIONS_FILE, []);
  const session = sessions.find((item) => item && item.id === sessionId) || null;
  const attendance = readJsonFile(ATTENDANCE_LOG_FILE, [])
    .filter((entry) => entry && (!sessionId || entry.sessionId === sessionId))
    .sort((a, b) => new Date(a.checkedInAt || 0) - new Date(b.checkedInAt || 0));

  const title = session?.course || attendance[0]?.course || (sessionId ? "Session Attendance Report" : "Attendance Report");
  const pdf = createAttendancePdf({
    title,
    session,
    sessionId,
    attendance
  });
  const fileSafeTitle = title.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "attendance-report";

  await sendEmail({
    to: adminEmail,
    subject: `GeoAttend PDF Report: ${title}`,
    text: `Attached is the GeoAttend attendance PDF report for ${title}.\n\nStudents checked in: ${attendance.length}`,
    html: `
      <div style="font-family:Inter,Arial,sans-serif;line-height:1.5;color:#0b1c30">
        <h2>GeoAttend Attendance Report</h2>
        <p><strong>Session:</strong> ${escapeHtml(title)}</p>
        <p><strong>Students checked in:</strong> ${attendance.length}</p>
        <p>The PDF report is attached to this email.</p>
      </div>
    `,
    attachments: [
      {
        filename: `${fileSafeTitle}.pdf`,
        content: pdf,
        contentType: "application/pdf"
      }
    ]
  });

  appendLog(SERVER_OUT_LOG, `Attendance PDF emailed to ${maskEmail(adminEmail)} | sessionId=${sessionId || "all"} | records=${attendance.length}`);
  json(res, 200, { ok: true, message: `PDF report sent to ${adminEmail}.`, sentTo: adminEmail, records: attendance.length });
}

async function saveAttendance(res, record) {
  if (!record || typeof record !== "object") {
    json(res, 400, { error: "A valid attendance record is required." });
    return;
  }

  if (record.action !== "check-out") {
    json(res, 403, { error: "Camera fingerprint verification is required for every check-in. Use the student Check In camera scan." });
    return;
  }

  const sessionId = String(record.sessionId || "").trim();
  if (!sessionId) {
    json(res, 400, { error: "Attendance requires a valid session id." });
    return;
  }

  const { items: liveSessionsForCheckin } = await readLiveSessionsStore();
  const session = liveSessionsForCheckin.find((item) => item && item.id === sessionId);
  if (!session || session.status !== "active") {
    json(res, 403, { error: "This attendance session is not active." });
    return;
  }
  const isAssisted = record.checkinType === "assisted-student" || record.assisted === true;
  if (isAssisted || record.assistedByRegNumber || record.targetRegNumber) {
    json(res, 403, { error: "Student-assisted check-in is disabled. Each student must check in personally." });
    return;
  }
  let email = String(record.email || "").trim().toLowerCase();
  let fullName = String(record.fullName || "").trim();
  let regNumber = normalizeRegNumber(record.regNumber);
  const students = await readStudentsStore();
  const studentForSignature = students.find((student) => (
    (email && student.email === email) || (regNumber && normalizeRegNumber(student.regNumber) === regNumber)
  )) || null;
  if (studentForSignature) {
    email = String(studentForSignature.email || email).trim().toLowerCase();
    fullName = String(studentForSignature.fullName || fullName).trim();
    regNumber = normalizeRegNumber(studentForSignature.regNumber || regNumber);
  }

  if (!email && regNumber) email = `${regNumber.toLowerCase()}@reg.geoattend.local`;
  if (!regNumber) regNumber = normalizeRegNumber(record.regNumber) || "--";
  if (!email || (!isEmail(email) && !email.endsWith("@reg.geoattend.local"))) {
    json(res, 400, { error: "Attendance requires a valid student registration number." });
    return;
  }

  const action = record.action === "check-out" ? "check-out" : "check-in";
  const checkinToken = String(record.checkinToken || "");
  const authorization = attendanceAuthorizationStore.get(checkinToken);
  if (!authorization || authorization.expiresAt < Date.now() || authorization.email !== email || authorization.sessionId !== sessionId || authorization.action !== action) {
    json(res, 403, { error: `Verify your own fingerprint immediately before checking ${action === "check-out" ? "out" : "in"}.` });
    return;
  }
  attendanceAuthorizationStore.delete(checkinToken);
  const { items: attendance } = await readAttendanceStore();
  const existing = attendance.find((entry) => entry && entry.sessionId === sessionId && (
    (regNumber !== "--" && normalizeRegNumber(entry.regNumber) === regNumber)
    || String(entry.email || "").trim().toLowerCase() === email
  ));
  const now = new Date();
  const getWindowDate = (value, fallback) => {
    const time = /^\d{2}:\d{2}$/.test(String(value || "")) ? String(value) : fallback;
    if (!time) return null;
    const base = session.date ? new Date(`${session.date}T00:00:00`) : session.createdAt ? new Date(session.createdAt) : new Date();
    if (Number.isNaN(base.getTime())) return null;
    const [hour, minute] = time.split(":").map(Number);
    const date = new Date(base);
    date.setHours(hour, minute, 0, 0);
    return date;
  };
  const classStart = getWindowDate(session.startTime, session.attendanceStart);
  const classEnd = getSessionEndDate(session);
  const checkInStart = getWindowDate(session.checkInStartTime || session.attendanceStart, session.startTime);
  const checkInEnd = getWindowDate(session.checkInEndTime || session.attendanceEnd, session.startTime);
  const checkOutStart = getWindowDate(session.checkOutStartTime || session.attendanceStart, session.startTime);
  const checkOutEnd = getWindowDate(session.checkOutEndTime || getSessionEndTime(session) || session.endTime, session.startTime);
  for (const edge of [checkInStart, checkInEnd, checkOutStart, checkOutEnd]) {
    if (edge && classStart && edge < classStart) edge.setDate(edge.getDate() + 1);
  }
  if (action === "check-in") {
    if (existing) { json(res, 409, { error: "You have already checked in for this session." }); return; }
    if ((checkInStart && now < checkInStart) || (checkInEnd && now > checkInEnd) || (classEnd && now > classEnd)) {
      json(res, 403, { error: "Check-in is outside this session's check-in window." }); return;
    }
  } else {
    if (!existing?.checkedInAt) { json(res, 409, { error: "Check out is unavailable before check-in." }); return; }
    if (existing.checkedOutAt) { json(res, 409, { error: "You have already checked out for this session." }); return; }
    const checkedInTime = new Date(existing.checkedInAt);
    if (now <= checkedInTime) { json(res, 403, { error: "Check-out must be after check-in." }); return; }
    if ((checkOutStart && now < checkOutStart) || (checkOutEnd && now > checkOutEnd) || (classEnd && now > classEnd)) {
      json(res, 403, { error: "Check-out is outside this session's check-out window." }); return;
    }
  }
  const actionKey = `${sessionId}:${email}:${action}`;
  if (attendanceActionLocks.has(actionKey)) { json(res, 409, { error: `A ${action} is already being saved for this session.` }); return; }
  attendanceActionLocks.add(actionKey);
  const idKey = regNumber !== "--" ? `${sessionId}:${regNumber}` : `${sessionId}:${email}`;
  const id = record.id || crypto.createHash("sha256").update(idKey).digest("hex");
  if (action === "check-out") {
    const checkedOutAt = now.toISOString();
    const durationMinutes = Math.max(0, Math.floor((now.getTime() - new Date(existing.checkedInAt).getTime()) / 60000));
    const scheduledMinutes = classStart && classEnd ? Math.max(0, Math.floor((classEnd - classStart) / 60000)) : 0;
    const minimumPercent = Number(session.minimumDurationPercent || 0);
    const meetsMinimum = !minimumPercent || !scheduledMinutes || durationMinutes >= scheduledMinutes * minimumPercent / 100;
    const { checkInLocation: _legacyCheckInLocation, checkOutLocation: _legacyCheckOutLocation, position: _legacyPosition, gpsVerification: _legacyVerification, checkOutGpsVerification: _legacyCheckOutVerification, ...existingWithoutLocation } = existing;
    const normalizedRecord = {
      ...existingWithoutLocation,
      checkedOutAt,
      durationMinutes,
      status: meetsMinimum ? "present" : "incomplete",
      savedAt: checkedOutAt
    };
    const nextAttendance = attendance.map((entry) => entry?.id === existing.id ? normalizedRecord : entry);
    let source = "sqlite";
    try { ({ source } = await writeAttendanceStore(nextAttendance)); }
    finally { attendanceActionLocks.delete(actionKey); }
    json(res, 200, { ok: true, source, record: normalizedRecord, attendance: nextAttendance });
    return;
  }

  const checkedInAt = now.toISOString();
  const { position: _legacyPosition, geofence: _legacyGeofence, checkInLocation: _legacyCheckInLocation, checkOutLocation: _legacyCheckOutLocation, gpsVerification: _legacyVerification, checkOutGpsVerification: _legacyCheckOutVerification, ...recordWithoutLocation } = record;
  const normalizedRecord = {
    ...recordWithoutLocation,
    id,
    email,
    sessionId,
    academicSession: session.academicSession || DEFAULT_ACADEMIC_SESSION,
    fullName: fullName || email || "Unknown Student",
    regNumber,
    institutionId: record.institutionId || studentForSignature?.institutionId || session?.institutionId || "",
    facultyId: record.facultyId || studentForSignature?.facultyId || session?.facultyId || "",
    facultyName: record.facultyName || studentForSignature?.facultyName || session?.facultyName || "",
    departmentId: record.departmentId || studentForSignature?.departmentId || session?.departmentId || "",
    departmentName: record.departmentName || studentForSignature?.departmentName || session?.departmentName || "",
    levelId: record.levelId || studentForSignature?.levelId || session?.levelId || "",
    levelName: record.levelName || studentForSignature?.levelName || session?.levelName || "",
    signature: record.signature || fullName || email || "",
    signatureDataUrl: normalizeSignatureDataUrl(record.signatureDataUrl || studentForSignature?.signatureDataUrl || ""),
    signatureStrokes: normalizeSignatureStrokes(record.signatureStrokes || studentForSignature?.signatureStrokes || []),
    status: "incomplete",
    checkedInAt,
    checkedOutAt: null,
    durationMinutes: null,
    savedAt: new Date().toISOString()
  };

  const nextAttendance = [normalizedRecord, ...attendance].slice(0, 2000);

  let source = "sqlite";
  try { ({ source } = await writeAttendanceStore(nextAttendance)); }
  finally { attendanceActionLocks.delete(actionKey); }
  json(res, 200, { ok: true, source, record: normalizedRecord, attendance: nextAttendance });
}

async function updateAttendanceStatus(req, res, body) {
  const principal = getRequestPrincipal(req);
  if (!principal.admin) return json(res, 403, { error: "Admin access is required to edit attendance status." });
  const allowed = new Set(["present", "incomplete", "absent"]);
  if (!body?.recordId || !allowed.has(String(body.status || "").toLowerCase())) return json(res, 400, { error: "Choose a valid attendance record and status." });
  const { items: attendance } = await readAttendanceStore();
  const record = attendance.find((entry) => entry?.id === String(body.recordId));
  if (!record) return json(res, 404, { error: "Attendance record not found." });
  if (!entityMatchesScope(record, principal.admin, principal.admin.adminRole || principal.admin.role)) return json(res, 403, { error: "This attendance record is outside your admin scope." });
  const nextRecord = { ...record, status: String(body.status).toLowerCase(), manuallyEditedAt: new Date().toISOString(), manuallyEditedBy: principal.admin.email };
  const nextAttendance = attendance.map((entry) => entry?.id === record.id ? nextRecord : entry);
  const { source } = await writeAttendanceStore(nextAttendance);
  return json(res, 200, { ok: true, source, record: nextRecord, attendance: nextAttendance });
}

function normalizeAdminRole(value) {
  const raw = String(value || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (["owner", "overall", "overall_admin", "super_admin"].includes(raw)) return "overall_admin";
  if (["building", "building_admin", "buildingadmin", "map_admin", "map_building_admin"].includes(raw)) return "building_admin";
  if (["faculty", "faculty_admin"].includes(raw)) return "faculty_admin";
  if (["level", "level_admin"].includes(raw)) return "level_admin";
  if (["lecturer", "lecturer_admin", "lectureradmin"].includes(raw)) return "lecturer_admin";
  return "department_admin";
}

function getRoleLabel(role) {
  return {
    overall_admin: "Overall Admin",
    building_admin: "Building Admin",
    faculty_admin: "Faculty Admin",
    department_admin: "Department Admin",
    level_admin: "Level Admin",
    lecturer_admin: "Lecturer Admin"
  }[normalizeAdminRole(role)] || "Department Admin";
}

function getScopeLabel(scope = {}) {
  const parts = [scope.facultyName, scope.departmentName, scope.levelName].filter(Boolean);
  return parts.length ? parts.join(" / ") : ACADEMIC_SCOPE.institution.name;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(String(password || ""), salt, 120000, 32, "sha256").toString("hex");
  return `pbkdf2:${salt}:${hash}`;
}

function verifyStoredPassword(password, admin) {
  const storedHash = String(admin?.passwordHash || "");
  if (storedHash.startsWith("pbkdf2:")) {
    const [, salt, expected] = storedHash.split(":");
    if (!salt || !expected) return false;
    const actual = crypto.pbkdf2Sync(String(password || ""), salt, 120000, 32, "sha256").toString("hex");
    return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
  }
  return String(admin?.password || "") === String(password || "");
}

function isRateLimited(store, key, limit, windowMs) {
  const now = Date.now();
  const attempts = (store.get(key) || []).filter((time) => now - time < windowMs);
  attempts.push(now);
  store.set(key, attempts);
  return attempts.length > limit;
}

function findAdminByIdentifier(identifier) {
  const value = String(identifier || "").trim().toLowerCase();
  const reg = normalizeRegNumber(identifier);
  if (!value && !reg) return null;
  return getAdminRoster().find((admin) => (
    (admin.email && admin.email === value) ||
    (reg && admin.regNumber === reg)
  )) || null;
}

function getRequestPrincipal(req) {
  const url = new URL(req.url, "http://127.0.0.1");
  return {
    admin: findAdminByIdentifier(url.searchParams.get("actorEmail") || url.searchParams.get("adminEmail") || ""),
    studentEmail: String(url.searchParams.get("email") || "").trim().toLowerCase()
  };
}

async function getStudentByEmail(email) {
  const target = String(email || "").trim().toLowerCase();
  if (!target) return null;
  const students = await readStudentsStore();
  return students.find((student) => String(student.email || "").trim().toLowerCase() === target) || null;
}

function entityMatchesScope(entity = {}, scope = {}, role = "overall_admin") {
  const normalizedRole = normalizeAdminRole(role);
  if (normalizedRole === "overall_admin" || normalizedRole === "lecturer_admin") return true;
  if (normalizedRole === "faculty_admin") return !scope.facultyId || entity.facultyId === scope.facultyId;
  if (normalizedRole === "department_admin") return !scope.departmentId || entity.departmentId === scope.departmentId;
  if (normalizedRole === "level_admin") {
    return (!scope.departmentId || entity.departmentId === scope.departmentId) && (!scope.levelId || entity.levelId === scope.levelId);
  }
  return true;
}

function applyAdminScopeToSession(session = {}, admin = null) {
  const selected = normalizeAcademicScope(session);
  if (!admin) return { ...session, ...selected };
  const adminRole = normalizeAdminRole(admin.adminRole || admin.role);
  const adminScope = normalizeAcademicScope(admin);
  const next = { ...session, ...selected, createdBy: admin.email || admin.regNumber || session.createdBy || "", createdByAdminRole: adminRole };
  if (adminRole === "overall_admin" || adminRole === "lecturer_admin") return next;
  if (adminRole === "faculty_admin") {
    return { ...next, facultyId: adminScope.facultyId, facultyName: adminScope.facultyName };
  }
  if (adminRole === "department_admin") {
    return { ...next, facultyId: adminScope.facultyId, facultyName: adminScope.facultyName, departmentId: adminScope.departmentId, departmentName: adminScope.departmentName };
  }
  return { ...next, ...adminScope };
}

async function filterSessionsForRequest(req, sessions) {
  const { admin, studentEmail } = getRequestPrincipal(req);
  if (admin) {
    if (isLecturerAdmin(admin)) {
      const assignedCodes = new Set(await getLecturerAssignedCourseCodes(admin.email));
      return sessions.filter((session) => assignedCodes.has(getCourseCode(session.course)));
    }
    return sessions.filter((session) => entityMatchesScope(session, admin, admin.adminRole || admin.role));
  }
  if (studentEmail) {
    const student = await getStudentByEmail(studentEmail);
    if (!student) return [];
    return sessions.filter((session) => (!session.departmentId || session.departmentId === student.departmentId) && (!session.levelId || session.levelId === student.levelId));
  }
  return sessions;
}

async function filterReportsForRequest(req, reports) {
  const { admin } = getRequestPrincipal(req);
  if (!admin) return reports;
  if (isLecturerAdmin(admin)) {
    const assignedCodes = new Set(await getLecturerAssignedCourseCodes(admin.email));
    return reports.filter((report) => assignedCodes.has(getCourseCode(report.course || report.title)));
  }
  return reports.filter((report) => entityMatchesScope(report, admin, admin.adminRole || admin.role));
}

function copyDirectorySync(source, target) {
  if (!fs.existsSync(source)) return;
  fs.mkdirSync(target, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const src = path.join(source, entry.name);
    const dst = path.join(target, entry.name);
    if (entry.isDirectory()) copyDirectorySync(src, dst);
    else fs.copyFileSync(src, dst);
  }
}

function createBackup(res, body) {
  const actorEmail = String(body.actorEmail || "").trim().toLowerCase();
  if (!isOwnerAdmin(actorEmail)) {
    json(res, 403, { error: "Only the overall admin can create backups." });
    return;
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(BACKUP_DIR, `geoattend-${stamp}`);
  fs.mkdirSync(backupPath, { recursive: true });
  [SQLITE_DB_FILE, LIVE_SESSIONS_FILE, ATTENDANCE_LOG_FILE, STUDENTS_FILE, ADMIN_USERS_FILE, ATTENDANCE_REPORTS_INDEX_FILE].forEach((file) => {
    if (fs.existsSync(file)) fs.copyFileSync(file, path.join(backupPath, path.basename(file)));
  });
  copyDirectorySync(ATTENDANCE_REPORTS_DIR, path.join(backupPath, "attendance-reports"));
  const manifest = { createdAt: new Date().toISOString(), createdBy: actorEmail, files: fs.readdirSync(backupPath) };
  fs.writeFileSync(path.join(backupPath, "manifest.json"), JSON.stringify(manifest, null, 2));
  json(res, 200, { ok: true, backupPath, manifest });
}
function getAdminRoster() {
  const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || "");
  const extraAdmins = readJsonFile(ADMIN_USERS_FILE, []);
  const defaults = getAcademicDefaults();
  const roster = [];
  if (isEmail(adminEmail) && adminPassword) {
    roster.push({
      email: adminEmail,
      fullName: String(process.env.ADMIN_NAME || process.env.ADMIN_FULL_NAME || "").trim(),
      password: adminPassword,
      adminRole: "overall_admin",
      role: "owner",
      ...defaults,
      createdAt: "system"
    });
  }
  extraAdmins.forEach((admin) => {
    const email = String(admin.email || "").trim().toLowerCase();
    const regNumber = normalizeRegNumber(admin.regNumber);
    if (!regNumber && !isEmail(email)) return;
    if (roster.some((item) => (email && item.email === email) || (regNumber && item.regNumber === regNumber))) return;
    const scope = normalizeAcademicScope(admin);
    const adminRole = normalizeAdminRole(admin.adminRole || admin.role);
    roster.push({
      email,
      fullName: String(admin.fullName || "").trim(),
      regNumber,
      password: String(admin.password || ""),
      passwordHash: admin.passwordHash || "",
      adminRole,
      role: adminRole,
      ...scope,
      createdAt: admin.createdAt || null,
      createdBy: admin.createdBy || ""
    });
  });
  return roster;
}

function isOwnerAdmin(email) {
  return String(email || "").trim().toLowerCase() === String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
}

function adminPublicView(admin) {
  const adminRole = normalizeAdminRole(admin.adminRole || admin.role);
  return {
    email: admin.email,
    fullName: admin.fullName || "",
    regNumber: admin.regNumber || "",
    role: admin.role,
    adminRole,
    roleLabel: getRoleLabel(adminRole),
    institutionId: admin.institutionId || "",
    facultyId: admin.facultyId || "",
    facultyName: admin.facultyName || "",
    departmentId: admin.departmentId || "",
    departmentName: admin.departmentName || "",
    levelId: admin.levelId || "",
    levelName: admin.levelName || "",
    scopeLabel: getScopeLabel(admin),
    createdAt: admin.createdAt || null
  };
}

function getAdmins(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const actorEmail = String(url.searchParams.get("actorEmail") || "").trim().toLowerCase();
  if (!isOwnerAdmin(actorEmail)) {
    json(res, 403, { error: "Only the overall admin can manage admins." });
    return;
  }
  json(res, 200, {
    ok: true,
    ownerEmail: String(process.env.ADMIN_EMAIL || "").trim().toLowerCase(),
    admins: getAdminRoster().map(adminPublicView)
  });
}

function normalizeRegNumber(value) {
  const raw = String(value || "").trim().toUpperCase();
  if (!raw) return "";
  return raw;
}

async function findRegisteredStudentByRegNumber(regNumber) {
  const normalizedReg = normalizeRegNumber(regNumber);
  if (!normalizedReg) return null;
  const students = await readStudentsStore();
  return students.find((student) => String(student.regNumber || "").trim().toUpperCase() === normalizedReg) || null;
}

async function saveAdminUser(res, body) {
  const actorEmail = String(body.actorEmail || "").trim().toLowerCase();
  if (!isOwnerAdmin(actorEmail)) {
    json(res, 403, { error: "Only the overall admin can add admins." });
    return;
  }

  const regNumber = normalizeRegNumber(body.regNumber);
  const student = await findRegisteredStudentByRegNumber(regNumber);
  if (!student) {
    json(res, 404, { error: "No registered student was found for that registration number." });
    return;
  }

  const email = String(student.email || "").trim().toLowerCase();
  const fullName = String(student.fullName || "").trim();
  if (!fullName) {
    json(res, 400, { error: "The linked student does not have a full name." });
    return;
  }
  if (email && isOwnerAdmin(email)) {
    json(res, 400, { error: "The overall admin already exists." });
    return;
  }

  const adminRole = normalizeAdminRole(body.adminRole || "department_admin");
  const studentRow = await dbGet("SELECT password_hash FROM students WHERE reg_number = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1", [regNumber, email]);
  const studentPasswordHash = String(studentRow?.password_hash || student.passwordHash || student.password_hash || "");
  const scope = normalizeAcademicScope({ ...student, ...body });
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const admins = readJsonFile(ADMIN_USERS_FILE, []).filter((admin) => {
    if (!admin) return false;
    const adminEmail = String(admin.email || "").trim().toLowerCase();
    const adminReg = normalizeRegNumber(admin.regNumber);
    return adminReg !== regNumber && (!email || adminEmail !== email);
  });
  const record = {
    email,
    fullName,
    regNumber,
    passwordHash: studentPasswordHash || hashPassword(regNumber),
    adminRole,
    role: adminRole,
    ...scope,
    createdAt: new Date().toISOString(),
    createdBy: actorEmail
  };
  admins.unshift(record);
  fs.writeFileSync(ADMIN_USERS_FILE, JSON.stringify(admins, null, 2));
  json(res, 200, { ok: true, admin: adminPublicView(record), admins: getAdminRoster().map(adminPublicView) });
}

function removeAdminUser(res, body) {
  const actorEmail = String(body.actorEmail || "").trim().toLowerCase();
  if (!isOwnerAdmin(actorEmail)) {
    json(res, 403, { error: "Only the overall admin can remove admins." });
    return;
  }

  const regNumber = normalizeRegNumber(body.regNumber);
  const admins = readJsonFile(ADMIN_USERS_FILE, []);
  if (!regNumber) {
    json(res, 400, { error: "Enter the registration number of an admin to remove." });
    return;
  }

  const matchedAdmin = admins.find((admin) => normalizeRegNumber(admin.regNumber) === regNumber);
  if (!matchedAdmin) {
    json(res, 404, { error: "No admin was found for that registration number." });
    return;
  }

  const email = String(matchedAdmin.email || "").trim().toLowerCase();
  if (email && isOwnerAdmin(email)) {
    json(res, 400, { error: "The overall admin cannot be removed." });
    return;
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });
  const nextAdmins = admins.filter((admin) => admin && normalizeRegNumber(admin.regNumber) !== regNumber);
  fs.writeFileSync(ADMIN_USERS_FILE, JSON.stringify(nextAdmins, null, 2));
  json(res, 200, { ok: true, admins: getAdminRoster().map(adminPublicView) });
}

async function studentLogin(res, body) {
  const identifier = String(body.email || body.regNumber || "").trim();
  const email = identifier.toLowerCase();
  const regNumber = normalizeRegNumber(identifier);
  const password = String(body.password || "");
  if (!identifier || !password) {
    json(res, 400, { error: "Email/reg number and password are required." });
    return;
  }
  const key = email || regNumber || "unknown";
  if (isRateLimited(loginAttemptStore, `student:${key}`, 10, 10 * 60 * 1000)) {
    json(res, 429, { error: "Too many login attempts. Try again in a few minutes." });
    return;
  }
  const row = await dbGet("SELECT * FROM students WHERE email = ? COLLATE NOCASE OR reg_number = ? COLLATE NOCASE LIMIT 1", [email, regNumber]);
  if (!row) {
    json(res, 404, { error: "No student account was found. Please register first." });
    return;
  }
  const passwordHash = String(row.password_hash || "");
  if (!passwordHash) {
    json(res, 409, { error: "This student account needs password re-sync. Please reset password or register again." });
    return;
  }
  if (!verifyStoredPassword(password, { passwordHash })) {
    json(res, 401, { error: "Incorrect password. Please try again." });
    return;
  }
  const student = sqliteStudentFromRow(row);
  json(res, 200, { ok: true, user: student });
}
function verifyAdminCredentials(identifier, password) {
  const email = String(identifier || "").trim().toLowerCase();
  const regNumber = normalizeRegNumber(identifier);
  const rawPassword = String(password || "");
  if ((!email && !regNumber) || !rawPassword) return null;
  return getAdminRoster().find((item) => (
    (item.email && item.email === email) || (regNumber && item.regNumber === regNumber)
  ) && verifyStoredPassword(rawPassword, item)) || null;
}
async function verifyAdminCredentialsForLogin(identifier, password) {
  const directAdmin = verifyAdminCredentials(identifier, password);
  if (directAdmin) return directAdmin;

  const email = String(identifier || "").trim().toLowerCase();
  const regNumber = normalizeRegNumber(identifier);
  const candidate = getAdminRoster().find((item) => (
    (item.email && item.email === email) || (regNumber && item.regNumber === regNumber)
  ));
  if (!candidate) return null;

  const row = await dbGet("SELECT password_hash FROM students WHERE email = ? COLLATE NOCASE OR reg_number = ? COLLATE NOCASE LIMIT 1", [candidate.email || email, candidate.regNumber || regNumber]);
  const passwordHash = String(row?.password_hash || "");
  if (passwordHash && verifyStoredPassword(password, { passwordHash })) {
    return { ...candidate, passwordHash };
  }
  return null;
}

async function adminLogin(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const regNumber = normalizeRegNumber(body.email || body.regNumber);
  const password = String(body.password || "");
  const key = email || regNumber || "unknown";
  if (isRateLimited(loginAttemptStore, `admin:${key}`, 8, 10 * 60 * 1000)) {
    json(res, 429, { error: "Too many login attempts. Try again in a few minutes." });
    return;
  }
  const roster = getAdminRoster();
  const admin = await verifyAdminCredentialsForLogin(email || regNumber, password);

  if (!roster.length) {
    json(res, 500, { error: "Admin login is not configured. Add ADMIN_EMAIL and ADMIN_PASSWORD to .env." });
    return;
  }

  if (!admin) {
    json(res, 401, { error: "Invalid admin email/reg number or password." });
    return;
  }

  const publicAdmin = adminPublicView(admin);
  json(res, 200, {
    ok: true,
    user: {
      ...publicAdmin,
      role: "admin",
      verified: true
    }
  });
}
function getClientIp(req) {
  const forwardedFor = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  const rawIp = forwardedFor || req.socket.remoteAddress || "";
  return rawIp.replace(/^::ffff:/, "");
}

function saveAdminLoginAudit(req, res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  if (!getAdminRoster().some((admin) => admin.email === email)) {
    json(res, 403, { error: "Only the configured admin account can write admin login audit records." });
    return;
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });
  const audits = readJsonFile(ADMIN_LOGIN_AUDIT_FILE, []);
  const audit = {
    id: `admin-audit-${Date.now()}`,
    email,
    loginTime: new Date().toISOString(),
    ipAddress: getClientIp(req),
    device: {
      userAgent: req.headers["user-agent"] || body.device?.userAgent || "",
      platform: body.device?.platform || "",
      language: body.device?.language || "",
      timezone: body.device?.timezone || ""
    }
  };

  audits.unshift(audit);
  fs.writeFileSync(ADMIN_LOGIN_AUDIT_FILE, JSON.stringify(audits.slice(0, 500), null, 2));
  json(res, 200, { ok: true, audit });
}

function googleMapsConfig(res) {
  const apiKey = String(process.env.GOOGLE_MAPS_API_KEY || "").trim();
  if (!apiKey) {
    json(res, 500, { error: "Google Maps is not configured. Add GOOGLE_MAPS_API_KEY to .env." });
    return;
  }

  json(res, 200, { apiKey });
}

function getFirebaseDatabaseUrl() {
  return String(process.env.FIREBASE_DATABASE_URL || process.env.FIREBASE_DB_URL || "").trim().replace(/\/+$/, "");
}

function getFirebaseTimeoutMs() {
  const configured = Number(process.env.FIREBASE_TIMEOUT_MS || 3500);
  return Number.isFinite(configured) && configured >= 1000 ? configured : 3500;
}

function firebaseRequest(method, resourcePath, payload = null) {
  const databaseUrl = getFirebaseDatabaseUrl();
  if (!databaseUrl) return Promise.resolve(null);

  return new Promise((resolve, reject) => {
    const url = new URL(`${databaseUrl}/${resourcePath.replace(/^\/+/, "")}.json`);
    const requestBody = payload ? JSON.stringify(payload) : null;
    const request = https.request(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(requestBody ? { "Content-Length": Buffer.byteLength(requestBody) } : {})
      }
    }, (response) => {
      let body = "";
      response.on("data", (chunk) => body += chunk);
      response.on("end", () => {
        let data = null;
        try {
          data = body ? JSON.parse(body) : null;
        } catch {
          reject(new Error("Firebase returned an invalid response."));
          return;
        }
        if (response.statusCode >= 400) {
          reject(new Error(data?.error || `Firebase request failed with ${response.statusCode}.`));
          return;
        }
        resolve(data);
      });
    });

    request.on("error", reject);
    request.setTimeout(getFirebaseTimeoutMs(), () => {
      request.destroy(new Error("Firebase request timed out."));
    });
    if (requestBody) request.write(requestBody);
    request.end();
  });
}

function firebaseCollectionToArray(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (value && typeof value === "object") return Object.values(value).filter(Boolean);
  return [];
}

function writeLocalJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function realtimeItemKey(item, index) {
  if (!item || typeof item !== "object") return `index:${index}`;
  if (item.id) return `id:${item.id}`;
  if (item.sessionId && (item.regNumber || item.email)) return `attendance:${item.sessionId}:${normalizeRegNumber(item.regNumber) || String(item.email || "").toLowerCase()}`;
  if (item.email) return `email:${String(item.email).toLowerCase()}`;
  if (item.regNumber) return `reg:${normalizeRegNumber(item.regNumber)}`;
  return `index:${index}`;
}

function mergeRealtimeItems(remoteItems, localItems) {
  const merged = new Map();
  remoteItems.forEach((item, index) => merged.set(realtimeItemKey(item, index), item));
  localItems.forEach((item, index) => {
    const key = realtimeItemKey(item, index);
    if (!merged.has(key)) merged.set(key, item);
  });
  return Array.from(merged.values()).filter(Boolean);
}
async function readRealtimeArrayStore(resourcePath, filePath, fallback = []) {
  const firebaseData = await firebaseRequest("GET", resourcePath).catch((error) => {
    appendLog(SERVER_ERR_LOG, `Firebase ${resourcePath} read failed | ${error.message}`);
    return null;
  });

  if (firebaseData && typeof firebaseData === "object") {
    const remoteItems = firebaseCollectionToArray(firebaseData);
    const localItems = readJsonFile(filePath, fallback);
    const items = mergeRealtimeItems(remoteItems, Array.isArray(localItems) ? localItems : []);
    writeLocalJson(filePath, items);
    if (items.length !== remoteItems.length) {
      firebaseRequest("PUT", resourcePath, items).catch((error) => {
        appendLog(SERVER_ERR_LOG, `Firebase ${resourcePath} fallback sync failed | ${error.message}`);
      });
    }
    return { items, source: "firebase-realtime-db" };
  }

  return { items: readJsonFile(filePath, fallback), source: "local-json-fallback" };
}

async function writeRealtimeArrayStore(resourcePath, filePath, items) {
  const normalizedItems = Array.isArray(items) ? items.filter(Boolean) : [];
  writeLocalJson(filePath, normalizedItems);
  const firebaseResult = await firebaseRequest("PUT", resourcePath, normalizedItems).catch((error) => {
    appendLog(SERVER_ERR_LOG, `Firebase ${resourcePath} write failed | ${error.message}`);
    return null;
  });
  return {
    items: normalizedItems,
    source: getFirebaseDatabaseUrl() && firebaseResult !== null ? "firebase-realtime-db" : "local-json-fallback"
  };
}

async function readLiveSessionsStore() {
  return { items: await readSqliteSessions(), source: "sqlite" };
}

async function writeLiveSessionsStore(sessions) {
  await writeSqliteSessions(sessions);
  return { items: sessions, source: "sqlite" };
}

async function readAttendanceStore() {
  return { items: await readSqliteAttendance(), source: "sqlite" };
}

async function writeAttendanceStore(attendance) {
  await writeSqliteAttendance(attendance);
  return { items: attendance, source: "sqlite" };
}

function studentFirebaseKey(email) {
  return crypto.createHash("sha256").update(String(email || "").trim().toLowerCase()).digest("hex");
}

function normalizeSignatureDataUrl(value) {
  const text = String(value || "");
  return text.startsWith("data:image/png;base64,") && text.length <= 250000 ? text : "";
}

function normalizeSignatureStrokes(strokes) {
  if (!Array.isArray(strokes)) return [];
  return strokes.slice(0, 30).map((stroke) => {
    if (!Array.isArray(stroke)) return [];
    return stroke.slice(0, 500).map((point) => {
      const x = Number(point?.x);
      const y = Number(point?.y);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
      return {
        x: Math.max(0, Math.min(1, x)),
        y: Math.max(0, Math.min(1, y))
      };
    }).filter(Boolean);
  }).filter((stroke) => stroke.length > 1);
}

function publicStudent(student) {
  const scope = normalizeAcademicScope(student);
  return {
    id: student.id || studentFirebaseKey(student.email),
    fullName: String(student.fullName || ""),
    regNumber: String(student.regNumber || ""),
    email: String(student.email || "").trim().toLowerCase(),
    role: student.role || "student",
    verified: student.verified !== false,
    signatureDataUrl: normalizeSignatureDataUrl(student.signatureDataUrl),
    signatureStrokes: normalizeSignatureStrokes(student.signatureStrokes),
    institutionId: scope.institutionId,
    institutionName: scope.institutionName,
    facultyId: scope.facultyId,
    facultyName: scope.facultyName,
    departmentId: scope.departmentId,
    departmentName: scope.departmentName,
    levelId: scope.levelId,
    levelName: scope.levelName,
    createdAt: student.createdAt || null,
    updatedAt: student.updatedAt || null
  };
}

function sortStudents(students) {
  return students.sort((a, b) => {
    const aNum = Number((String(a.regNumber || "").match(/\d+/g) || ["999999"]).at(-1));
    const bNum = Number((String(b.regNumber || "").match(/\d+/g) || ["999999"]).at(-1));
    return (aNum - bNum) || String(a.regNumber || "").localeCompare(String(b.regNumber || ""), undefined, { numeric: true });
  });
}

async function readStudentsStore() {
  return readSqliteStudents();
}

async function writeStudentStore(student) {
  const normalized = publicStudent({
    ...student,
    id: studentFirebaseKey(student.email),
    role: "student",
    verified: student.verified !== false,
    updatedAt: new Date().toISOString()
  });

  await upsertSqliteStudent({
    ...normalized,
    passwordHash: student.passwordHash || student.password_hash || "",
    totpSecret: student.totpSecret || student.totp_secret || "",
    totpEnabled: student.totpEnabled || student.totp_enabled || false
  });
  const students = (await readSqliteStudents()).filter((item) => item && item.email !== normalized.email && String(item.regNumber || "").toLowerCase() !== normalized.regNumber.toLowerCase());
  writeLocalJson(STUDENTS_FILE, sortStudents([normalized, ...students]));
  return normalized;
}

function normalizeStudentPresence(item = {}) {
  return {
    email: String(item.email || "").trim().toLowerCase(),
    fullName: String(item.fullName || "").trim(),
    regNumber: String(item.regNumber || "").trim().toUpperCase(),
    lastSeen: item.lastSeen || null
  };
}

async function updateStudentPresence(res, body) {
  const email = String(body?.email || "").trim().toLowerCase();
  if (!email) {
    json(res, 400, { error: "Student email is required." });
    return;
  }
  const student = (await readStudentsStore()).find((item) => String(item.email || "").trim().toLowerCase() === email);
  if (!student) {
    json(res, 403, { error: "Only a registered student can publish presence." });
    return;
  }
  const entries = readJsonFile(STUDENT_PRESENCE_FILE, []).map(normalizeStudentPresence).filter((item) => item.email);
  const next = normalizeStudentPresence({ email, fullName: student.fullName, regNumber: student.regNumber, lastSeen: new Date().toISOString() });
  writeLocalJson(STUDENT_PRESENCE_FILE, [next, ...entries.filter((item) => item.email !== email)].slice(0, 1000));
  json(res, 200, { ok: true, presence: next });
}

async function getStudentPresence(req, res) {
  const principal = getRequestPrincipal(req);
  if (!principal.admin) {
    json(res, 403, { error: "Admin access is required." });
    return;
  }
  const entries = readJsonFile(STUDENT_PRESENCE_FILE, []).map(normalizeStudentPresence).filter((item) => item.email);
  json(res, 200, { ok: true, presence: entries });
}
function normalizeStudentReport(item = {}) {
  return {
    id: String(item.id || ""),
    studentEmail: String(item.studentEmail || "").trim().toLowerCase(),
    studentName: String(item.studentName || "").trim(),
    regNumber: String(item.regNumber || "").trim().toUpperCase(),
    category: String(item.category || "Other").trim(),
    message: String(item.message || "").trim(),
    status: item.status === "handled" ? "handled" : "new",
    createdAt: item.createdAt || null,
    updatedAt: item.updatedAt || null
  };
}

async function getStudentReports(req, res) {
  const principal = getRequestPrincipal(req);
  const reports = readJsonFile(STUDENT_REPORTS_FILE, []).map(normalizeStudentReport).filter((item) => item.id);
  if (principal.admin) {
    json(res, 200, { ok: true, reports });
    return;
  }
  if (principal.studentEmail) {
    json(res, 200, { ok: true, reports: reports.filter((report) => report.studentEmail === principal.studentEmail) });
    return;
  }
  json(res, 403, { error: "A signed-in student or admin account is required." });
}

async function createStudentReport(res, body) {
  const email = String(body?.studentEmail || body?.email || "").trim().toLowerCase();
  const category = String(body?.category || "").trim().slice(0, 80);
  const message = String(body?.message || "").trim().slice(0, 2000);
  if (!email || !category || message.length < 5) {
    json(res, 400, { error: "Choose a report type and enter at least 5 characters." });
    return;
  }
  const student = (await readStudentsStore()).find((item) => String(item.email || "").trim().toLowerCase() === email);
  if (!student) {
    json(res, 403, { error: "Only a registered student can submit a report." });
    return;
  }
  const now = new Date().toISOString();
  const report = normalizeStudentReport({
    id: `student-report-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    studentEmail: email,
    studentName: student.fullName,
    regNumber: student.regNumber,
    category,
    message,
    status: "new",
    createdAt: now,
    updatedAt: now
  });
  const reports = readJsonFile(STUDENT_REPORTS_FILE, []).map(normalizeStudentReport).filter((item) => item.id);
  writeLocalJson(STUDENT_REPORTS_FILE, [report, ...reports].slice(0, 500));
  json(res, 201, { ok: true, report });
}

async function updateStudentReportStatus(res, body) {
  const actor = findAdminByIdentifier(body?.actorEmail || body?.adminEmail || "");
  const id = String(body?.id || "").trim();
  const status = body?.status === "new" ? "new" : "handled";
  if (!actor || !id) {
    json(res, 403, { error: "Admin access is required." });
    return;
  }
  const reports = readJsonFile(STUDENT_REPORTS_FILE, []).map(normalizeStudentReport);
  const index = reports.findIndex((item) => item.id === id);
  if (index < 0) {
    json(res, 404, { error: "Report not found." });
    return;
  }
  reports[index] = { ...reports[index], status, updatedAt: new Date().toISOString() };
  writeLocalJson(STUDENT_REPORTS_FILE, reports);
  json(res, 200, { ok: true, report: reports[index] });
}
async function getStudents(req, res) {
  const principal = getRequestPrincipal(req);
  const students = isLecturerAdmin(principal.admin) ? [] : sortStudents(await readStudentsStore());
  json(res, 200, {
    ok: true,
    source: "sqlite",
    students
  });
}

async function deleteStudentAccount(res, body) {
  const actorIdentifier = String(body.actorEmail || body.actorRegNumber || "").trim();
  const actorPassword = String(body.adminPassword || body.password || "");
  const actor = verifyAdminCredentials(actorIdentifier, actorPassword);
  if (!actor) {
    json(res, 403, { error: "Enter a valid admin password to delete this student." });
    return;
  }

  const email = String(body.email || "").trim().toLowerCase();
  const regNumber = normalizeRegNumber(body.regNumber);
  if (!email && !regNumber) {
    json(res, 400, { error: "Student email or registration number is required." });
    return;
  }

  const row = await dbGet("SELECT * FROM students WHERE email = ? COLLATE NOCASE OR reg_number = ? COLLATE NOCASE LIMIT 1", [email, regNumber]);
  if (!row) {
    json(res, 404, { error: "Student account was not found." });
    return;
  }

  const student = sqliteStudentFromRow(row);
  if (!entityMatchesScope(student, actor, actor.adminRole || actor.role)) {
    json(res, 403, { error: "You cannot delete a student outside your admin scope." });
    return;
  }

  const targetEmail = String(row.email || email || "").trim().toLowerCase();
  const targetReg = normalizeRegNumber(row.reg_number || regNumber);
  await dbRun("DELETE FROM biometric_profiles WHERE email = ? COLLATE NOCASE", [targetEmail]);
  await dbRun("DELETE FROM webauthn_credentials WHERE student_id = ?", [row.id]);

  const result = await dbRun("DELETE FROM students WHERE id = ?", [row.id]);

  const students = readJsonFile(STUDENTS_FILE, []).filter((item) => {
    const itemEmail = String(item?.email || "").trim().toLowerCase();
    const itemReg = normalizeRegNumber(item?.regNumber || item?.reg_number);
    return itemEmail !== targetEmail && itemReg !== targetReg;
  });
  writeLocalJson(STUDENTS_FILE, sortStudents(students));

  const profiles = readJsonFile(BIOMETRIC_PROFILES_FILE, {});
  Object.keys(profiles && typeof profiles === "object" ? profiles : {}).forEach((profileId) => {
    const profileEmail = String(profiles[profileId]?.email || "").trim().toLowerCase();
    if (profileEmail === targetEmail) delete profiles[profileId];
  });
  writeLocalJson(BIOMETRIC_PROFILES_FILE, profiles);

  const remainingStudents = sortStudents(await readStudentsStore());
  json(res, 200, {
    ok: true,
    deleted: result.changes || 0,
    student: {
      email: targetEmail,
      regNumber: targetReg,
      fullName: row.full_name || ""
    },
    students: remainingStudents
  });
}
async function saveStudent(res, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const fullName = String(body.fullName || "").trim();
  const regNumber = String(body.regNumber || "").trim().toUpperCase();

  if (!isEmail(email) || !fullName || !regNumber) {
    json(res, 400, { error: "Full name, registration number, and valid email are required." });
    return;
  }

  const existing = await readStudentsStore();
  const duplicate = existing.find((student) => (
    student.email === email || String(student.regNumber || "").toLowerCase() === regNumber.toLowerCase()
  ));
  if (duplicate && duplicate.email !== email) {
    json(res, 409, { error: "A student with this email or registration number already exists." });
    return;
  }
  const existingStudent = existing.find((student) => student.email === email) || null;
  const password = String(body.password || "");
  const passwordHash = password ? hashPassword(password) : "";

  if (body.registrationFlow === true) {
    await dbRun("DELETE FROM biometric_profiles WHERE email = ? COLLATE NOCASE", [email]);
    const studentRow = await dbGet("SELECT id FROM students WHERE email = ? COLLATE NOCASE", [email]);
    if (studentRow) await dbRun("DELETE FROM webauthn_credentials WHERE student_id = ?", [studentRow.id]);

    const profiles = readJsonFile(BIOMETRIC_PROFILES_FILE, {});
    Object.keys(profiles && typeof profiles === "object" ? profiles : {}).forEach((profileId) => {
      if (String(profiles[profileId]?.email || "").trim().toLowerCase() === email) delete profiles[profileId];
    });
    writeLocalJson(BIOMETRIC_PROFILES_FILE, profiles);
  }
  await writeStudentStore({
    ...existingStudent,
    fullName,
    regNumber,
    email,
    passwordHash,
    verified: body.verified !== false,
    signatureDataUrl: body.signatureDataUrl ?? existingStudent?.signatureDataUrl ?? "",
    signatureStrokes: Array.isArray(body.signatureStrokes) ? body.signatureStrokes : existingStudent?.signatureStrokes || [],
    facultyId: body.facultyId || existingStudent?.facultyId,
    facultyName: body.facultyName || existingStudent?.facultyName,
    departmentId: body.departmentId || existingStudent?.departmentId,
    departmentName: body.departmentName || existingStudent?.departmentName,
    levelId: body.levelId || existingStudent?.levelId,
    levelName: body.levelName || existingStudent?.levelName,
    totpSecret: body.totpSecret || body.totp_secret || "",
    totpEnabled: body.totpEnabled || body.totp_enabled || false,
    createdAt: body.createdAt || existingStudent?.createdAt || new Date().toISOString()
  });

  const students = sortStudents(await readStudentsStore());
  json(res, 200, { ok: true, student: students.find((student) => student.email === email), students });
}

function getRegistrationReset(res) {
  const reset = readJsonFile(REGISTRATION_RESET_FILE, null) || { version: "initial" };
  json(res, 200, { ok: true, ...reset });
}

function readJsonFile(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function createAttendancePdf({ title, session, attendance }) {
  const course = session?.course || title || attendance[0]?.course || "................................";
  const date = formatAttendanceSheetDate(session);
  const academicSession = session?.academicSession || attendance[0]?.academicSession || DEFAULT_ACADEMIC_SESSION;
  const rows = attendance.length ? attendance : [];
  const rowsPerPage = 20;
  const pages = [];
  for (let index = 0; index < Math.max(rows.length, 1); index += rowsPerPage) {
    pages.push(rows.slice(index, index + rowsPerPage));
  }

  const pageWidth = A4_PDF_WIDTH;
  const pageHeight = A4_PDF_HEIGHT;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold >>"
  ];
  const pageObjectIds = [];

  pages.forEach((pageRows, pageIndex) => {
    const content = createAttendanceTemplatePage({
      course,
      date,
      academicSession,
      pageIndex,
      pageRows,
      startIndex: pageIndex * rowsPerPage
    });
    const pageId = objects.length + 1;
    const contentId = pageId + 1;
    pageObjectIds.push(pageId);
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentId} 0 R >>`);
    objects.push(`<< /Length ${Buffer.byteLength(content, "utf8")} >>\nstream\n${content}\nendstream`);
  });

  objects[1] = `<< /Type /Pages /Kids [${pageObjectIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pageObjectIds.length} >>`;

  const chunks = ["%PDF-1.4\n"];
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(Buffer.byteLength(chunks.join(""), "utf8"));
    chunks.push(`${index + 1} 0 obj\n${object}\nendobj\n`);
  });
  const xrefOffset = Buffer.byteLength(chunks.join(""), "utf8");
  chunks.push(`xref\n0 ${objects.length + 1}\n`);
  chunks.push("0000000000 65535 f \n");
  offsets.slice(1).forEach((offset) => {
    chunks.push(`${String(offset).padStart(10, "0")} 00000 n \n`);
  });
  chunks.push(`trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`);
  return Buffer.from(chunks.join(""), "utf8");
}

function createAttendanceTemplatePage({ course, date, academicSession, pageRows, startIndex, pageIndex }) {
  const tableX = 54;
  const tableY = 520;
  const tableWidth = 487;
  const rowHeight = 23;
  const colSn = 28;
  const colName = 132;
  const colReg = 70;
  const colCheckIn = 58;
  const colCheckOut = 58;
  const colDuration = 48;
  const colStatus = 55;
  const colSignature = tableWidth - colSn - colName - colReg - colCheckIn - colCheckOut - colDuration - colStatus;
  const commands = [];

  pdfText(commands, "UNIVERSITY OF UYO", 297, 780, 15, "F2", "center");
  pdfText(commands, "FACULTY OF ENGINEERING", 297, 750, 15, "F2", "center");
  pdfText(commands, `DEPARTMENT OF ELECTRICAL/ELECTRONICS ENGINEERING ${academicSession}`, 297, 720, 13, "F2", "center");
  pdfText(commands, "CLASS ATTENDANCE", 297, 690, 15, "F2", "center");
  pdfTextBox(commands, `COURSE: ${course}`, tableX, 640, 330, 12, "F2", "left");
  pdfTextBox(commands, `DATE: ${date}`, tableX + tableWidth - 150, 640, 150, 12, "F2", "right");

  const totalRows = Math.max(pageRows.length, 1) + 1;
  pdfRect(commands, tableX, tableY - totalRows * rowHeight, tableWidth, totalRows * rowHeight);
  for (let index = 1; index <= totalRows; index += 1) {
    const y = tableY - index * rowHeight;
    pdfLine(commands, tableX, y, tableX + tableWidth, y);
  }
  const columns = [colSn, colName, colReg, colCheckIn, colCheckOut, colDuration, colStatus];
  columns.reduce((x, width) => { pdfLine(commands, x + width, tableY, x + width, tableY - totalRows * rowHeight); return x + width; }, tableX);

  const headers = ["#", "NAME", "REG NO", "IN", "OUT", "MIN", "STATUS", "SIGN"];
  let headerX = tableX;
  [...columns, colSignature].forEach((width, index) => { pdfText(commands, headers[index], headerX + 3, tableY - 14, 7, "F2"); headerX += width; });

  if (!pageRows.length) {
    pdfText(commands, "No checked-in students for this session yet.", tableX + colSn + 8, tableY - rowHeight - 13, 10, "F1");
  } else {
    pageRows.forEach((record, index) => {
      const rowY = tableY - (index + 1) * rowHeight - 13;
      const valueX = [tableX, tableX + colSn, tableX + colSn + colName, tableX + colSn + colName + colReg, tableX + colSn + colName + colReg + colCheckIn, tableX + colSn + colName + colReg + colCheckIn + colCheckOut, tableX + colSn + colName + colReg + colCheckIn + colCheckOut + colDuration];
      const elapsed = Number(record.durationMinutes ?? (record.checkedInAt ? Math.floor(((record.checkedOutAt ? new Date(record.checkedOutAt) : new Date()) - new Date(record.checkedInAt)) / 60000) : 0));
      const values = [String(startIndex + index + 1), truncateForPdf(String(record.fullName || record.email || "Unknown Student").toUpperCase(), 22), truncateForPdf(String(record.regNumber || "--").toUpperCase(), 12), record.checkedInAt ? new Date(record.checkedInAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "--", record.checkedOutAt ? new Date(record.checkedOutAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "--", elapsed ? String(elapsed) : "--", String(record.status || "incomplete").toUpperCase()];
      values.forEach((value, column) => pdfTextBox(commands, String(value), valueX[column] + 3, rowY, columns[column] - 5, 7, "F1", "left"));
      drawPdfSignature(commands, record, tableX + tableWidth - colSignature + 2, tableY - (index + 2) * rowHeight + 3, colSignature - 4, rowHeight - 6);
    });
  }

  if (pageIndex > 0) {
    pdfText(commands, `Page ${pageIndex + 1}`, 297, 36, 9, "F1", "center");
  }

  return commands.join("\n");
}

function drawUniversityLogo(commands, centerX, centerY) {
  commands.push("1 0 0 RG");
  pdfCircle(commands, centerX, centerY, 34);
  commands.push("0.55 0.16 0.08 RG");
  pdfCircle(commands, centerX, centerY, 27);
  commands.push("0 0 0 RG");
  pdfText(commands, "UNIVERSITY OF UYO", centerX, centerY + 19, 6, "F2", "center");
  pdfText(commands, "NIGERIA", centerX, centerY - 23, 6, "F2", "center");
  commands.push("0.1 0.45 0.2 rg");
  commands.push(`${centerX - 7} ${centerY - 4} m ${centerX - 1} ${centerY + 11} l ${centerX + 4} ${centerY - 4} l f`);
  commands.push("0.85 0.15 0.1 rg");
  commands.push(`${centerX + 4} ${centerY - 4} m ${centerX + 13} ${centerY + 8} l ${centerX + 10} ${centerY - 8} l f`);
  commands.push("0 0 0 rg");
}

function drawPdfSignature(commands, record, x, y, width, height) {
  const strokes = normalizeSignatureStrokes(record?.signatureStrokes || []);
  if (!strokes.length) {
    pdfTextBox(commands, String(record?.signature || record?.fullName || "").toUpperCase(), x, y + 4, width, 8, "F1", "center");
    return;
  }
  commands.push("0 0 0 RG 0.8 w");
  strokes.forEach((stroke) => {
    stroke.forEach((point, index) => {
      const px = x + point.x * width;
      const py = y + (1 - point.y) * height;
      commands.push(`${px.toFixed(2)} ${py.toFixed(2)} ${index === 0 ? "m" : "l"}`);
    });
    commands.push("S");
  });
}
function pdfText(commands, text, x, y, size = 10, font = "F1", align = "left") {
  const safeText = escapePdfText(text);
  const estimatedWidth = estimatePdfTextWidth(text, size);
  const textX = align === "center" ? x - (estimatedWidth / 2) : x;
  commands.push(`BT /${font} ${size} Tf ${textX.toFixed(2)} ${y.toFixed(2)} Td (${safeText}) Tj ET`);
}

function pdfTextBox(commands, text, x, y, width, size = 10, font = "F1", align = "left") {
  const fittedText = fitPdfText(text, width, size);
  const safeText = escapePdfText(fittedText);
  const estimatedWidth = estimatePdfTextWidth(fittedText, size);
  let textX = x;
  if (align === "center") textX = x + (width - estimatedWidth) / 2;
  if (align === "right") textX = x + width - estimatedWidth;
  commands.push(`BT /${font} ${size} Tf ${textX.toFixed(2)} ${y.toFixed(2)} Td (${safeText}) Tj ET`);
}

function estimatePdfTextWidth(text, size) {
  return String(text || "").length * size * 0.48;
}

function fitPdfText(text, width, size) {
  const value = String(text || "");
  if (estimatePdfTextWidth(value, size) <= width) return value;
  let fitted = value;
  while (fitted.length > 3 && estimatePdfTextWidth(`${fitted}...`, size) > width) {
    fitted = fitted.slice(0, -1);
  }
  return `${fitted.trimEnd()}...`;
}

function pdfLine(commands, x1, y1, x2, y2) {
  commands.push(`0 0 0 RG 0.7 w ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`);
}

function pdfRect(commands, x, y, width, height) {
  commands.push(`0 0 0 RG 0.8 w ${x.toFixed(2)} ${y.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re S`);
}

function pdfCircle(commands, x, y, radius) {
  const k = 0.5522847498;
  const c = radius * k;
  commands.push(`${(x + radius).toFixed(2)} ${y.toFixed(2)} m`);
  commands.push(`${(x + radius).toFixed(2)} ${(y + c).toFixed(2)} ${(x + c).toFixed(2)} ${(y + radius).toFixed(2)} ${x.toFixed(2)} ${(y + radius).toFixed(2)} c`);
  commands.push(`${(x - c).toFixed(2)} ${(y + radius).toFixed(2)} ${(x - radius).toFixed(2)} ${(y + c).toFixed(2)} ${(x - radius).toFixed(2)} ${y.toFixed(2)} c`);
  commands.push(`${(x - radius).toFixed(2)} ${(y - c).toFixed(2)} ${(x - c).toFixed(2)} ${(y - radius).toFixed(2)} ${x.toFixed(2)} ${(y - radius).toFixed(2)} c`);
  commands.push(`${(x + c).toFixed(2)} ${(y - radius).toFixed(2)} ${(x + radius).toFixed(2)} ${(y - c).toFixed(2)} ${(x + radius).toFixed(2)} ${y.toFixed(2)} c S`);
}

function escapePdfText(value) {
  return String(value || "").replace(/[\\()]/g, "\\$&");
}

function truncateForPdf(value, length) {
  const text = String(value || "");
  if (text.length <= length) return text;
  return `${text.slice(0, Math.max(0, length - 3))}...`;
}

function formatPdfDate(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatAttendanceSheetDate(session) {
  const value = session?.createdAt || session?.updatedAt || new Date().toISOString();
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "................................";
  return date.toLocaleDateString("en-GB");
}

function getSessionStartDate(session) {
  if (!session?.startTime) return null;
  const [hours, minutes] = String(session.startTime).split(":").map(Number);
  if (!Number.isFinite(hours) || !Number.isFinite(minutes)) return null;
  const base = session.date ? new Date(`${session.date}T00:00:00`) : session.createdAt ? new Date(session.createdAt) : new Date();
  if (Number.isNaN(base.getTime())) return null;
  const start = new Date(base);
  start.setHours(hours, minutes, 0, 0);
  return start;
}

function getSessionEndDate(session) {
  const endTime = getSessionEndTime(session);
  if (!endTime) return null;
  const start = getSessionStartDate(session);
  if (!start) return null;
  const [hours, minutes] = String(endTime).split(":").map(Number);
  if (!Number.isFinite(hours) || !Number.isFinite(minutes)) return null;
  const end = new Date(start);
  end.setHours(hours, minutes, 0, 0);
  if (end <= start) end.setDate(end.getDate() + 1);
  return end;
}

function getSessionEndTime(session) {
  if (session?.sessionEndTime) return session.sessionEndTime;
  if (session?.startTime && Number(session.duration) > 0) {
    const [hour, minute] = String(session.startTime).split(":").map(Number);
    if (Number.isFinite(hour) && Number.isFinite(minute)) {
      const total = (hour * 60 + minute + Number(session.duration)) % 1440;
      return `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
    }
  }
  return session?.endTime || "";
}

function otpKey(email, purpose) {
  return `${purpose}:${String(email || "").trim().toLowerCase()}`;
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function maskEmail(value) {
  return String(value || "").replace(/^(.).+(@.+)$/, "$1***$2");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[char]));
}
