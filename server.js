const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const QRCode = require("qrcode");
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require("@simplewebauthn/server");

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
const ADMIN_GEOFENCE_MAX_ACCURACY_METERS = 20;
const STUDENT_GPS_MAX_ACCURACY_METERS = 30;
const STUDENT_GPS_MAX_AGE_MS = 15 * 1000;
const MIN_GEOFENCE_RADIUS_METERS = 20;
const MAX_GEOFENCE_RADIUS_METERS = 5000;
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
      await setupRegistrationTotp(res, body);
      return;
    }

    if (req.method === "POST" && req.url === "/api/verify-registration-otp") {
      const body = await readJson(req);
      verifyRegistrationTotp(res, { email: body.email, code: body.otp });
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
      await getCourses(res);
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

    if (req.method === "POST" && req.url === "/api/save-biometric-profile") {
      const body = await readJson(req);
      await saveBiometricProfile(res, body);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/biometric-profile")) {
      await getBiometricProfile(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/api/live-sessions") {
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
    await dbRun("INSERT OR IGNORE INTO academic_courses (code, title, faculty_id, department_id, level_id) VALUES (?, ?, ?, ?, ?)", [course.code, course.title, course.facultyId, course.departmentId, course.levelId]);
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
    const rows = await dbAll("SELECT code, title, faculty_id, department_id, level_id FROM academic_courses ORDER BY code COLLATE NOCASE");
    return rows.map((row) => ({ code: row.code, title: row.title, facultyId: row.faculty_id, departmentId: row.department_id, levelId: row.level_id }));
  } catch {
    return ACADEMIC_SCOPE.courses;
  }
}

async function getAcademicScope(req, res) {
  let courses = await readAcademicCourses();
  const principal = getRequestPrincipal(req);
  if (principal.admin && isLecturerAdmin(principal.admin)) {
    const assignedCodes = new Set(await getLecturerAssignedCourseCodes(principal.admin.email));
    courses = courses.filter((course) => assignedCodes.has(course.code));
  }
  const scope = { ...ACADEMIC_SCOPE, courses };
  json(res, 200, { ok: true, scope, ...scope, defaults: getAcademicDefaults() });
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

async function getCourses(res) {
  json(res, 200, { ok: true, courses: await readAcademicCourses() });
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
  await dbRun(`INSERT INTO academic_courses (code, title, faculty_id, department_id, level_id)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(code) DO UPDATE SET
      title = excluded.title,
      faculty_id = excluded.faculty_id,
      department_id = excluded.department_id,
      level_id = excluded.level_id`, [code, title, scope.facultyId, scope.departmentId, scope.levelId]);
  json(res, 200, { ok: true, course: { code, title, facultyId: scope.facultyId, departmentId: scope.departmentId, levelId: scope.levelId }, courses: await readAcademicCourses() });
}

async function deleteCourse(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const code = String(url.searchParams.get("code") || "").trim().toUpperCase();
  if (!code) {
    json(res, 400, { error: "Course code is required." });
    return;
  }
  await dbRun("DELETE FROM academic_courses WHERE code = ? COLLATE NOCASE", [code]);
  json(res, 200, { ok: true, courses: await readAcademicCourses() });
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
  await seedAcademicScope();

  await dbRun(`CREATE TABLE IF NOT EXISTS biometric_profiles (
    profile_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    profile_json TEXT NOT NULL,
    saved_at TEXT NOT NULL
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_biometric_profiles_email ON biometric_profiles(email)");

  await dbRun(`CREATE TABLE IF NOT EXISTS live_sessions (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    session_json TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    ended_at TEXT
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_live_sessions_status_updated ON live_sessions(status, updated_at)");

  await dbRun(`CREATE TABLE IF NOT EXISTS attendance (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    email TEXT,
    reg_number TEXT,
    full_name TEXT,
    status TEXT NOT NULL DEFAULT 'present',
    checked_in_at TEXT,
    saved_at TEXT,
    attendance_json TEXT NOT NULL
  )`);
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance(session_id)");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_session_reg ON attendance(session_id, reg_number)");
  await dbRun("CREATE INDEX IF NOT EXISTS idx_attendance_checked_in ON attendance(checked_in_at)");
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
  for (const session of Array.isArray(sessions) ? sessions : []) {
    if (!session?.id) continue;
    await upsertSqliteSession(session);
  }

  const attendance = readJsonFile(ATTENDANCE_LOG_FILE, []);
  for (const record of Array.isArray(attendance) ? attendance : []) {
    if (!record?.id || !record?.sessionId) continue;
    await upsertSqliteAttendance(record);
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
  await dbRun(`INSERT INTO live_sessions (id, status, session_json, created_at, updated_at, ended_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      status = excluded.status,
      session_json = excluded.session_json,
      created_at = COALESCE(live_sessions.created_at, excluded.created_at),
      updated_at = excluded.updated_at,
      ended_at = excluded.ended_at`, [
    session.id,
    session.status || "active",
    JSON.stringify(session),
    session.createdAt || session.created_at || null,
    session.updatedAt || session.updated_at || new Date().toISOString(),
    session.endedAt || session.ended_at || null
  ]);
}

async function readSqliteSessions() {
  const rows = await dbAll("SELECT session_json FROM live_sessions ORDER BY datetime(updated_at) DESC");
  return rows.map((row) => parseJsonColumn(row.session_json, null)).filter(Boolean);
}

async function writeSqliteSessions(sessions) {
  for (const session of Array.isArray(sessions) ? sessions : []) {
    if (session?.id) await upsertSqliteSession(session);
  }
  writeLocalJson(LIVE_SESSIONS_FILE, sessions);
}

async function upsertSqliteAttendance(record) {
  await dbRun(`INSERT INTO attendance (id, session_id, email, reg_number, full_name, status, checked_in_at, saved_at, attendance_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      session_id = excluded.session_id,
      email = excluded.email,
      reg_number = excluded.reg_number,
      full_name = excluded.full_name,
      status = excluded.status,
      checked_in_at = excluded.checked_in_at,
      saved_at = excluded.saved_at,
      attendance_json = excluded.attendance_json`, [
    record.id,
    record.sessionId,
    record.email || "",
    record.regNumber || "",
    record.fullName || "",
    record.status || "present",
    record.checkedInAt || null,
    record.savedAt || new Date().toISOString(),
    JSON.stringify(record)
  ]);
}

async function readSqliteAttendance() {
  const rows = await dbAll("SELECT attendance_json FROM attendance ORDER BY datetime(checked_in_at) DESC");
  return rows.map((row) => parseJsonColumn(row.attendance_json, null)).filter(Boolean);
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
      if (data.length > 8e6) {
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
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

function setCorsHeaders(res) {
  Object.entries(getCorsHeaders()).forEach(([key, value]) => res.setHeader(key, value));
}

function getWebAuthnContext(req) {
  const host = String(req.headers.host || `127.0.0.1:${PORT}`).trim();
  const originHeader = String(req.headers.origin || "").trim();
  const fallbackProtocol = (req.socket && req.socket.encrypted) ? "https" : "http";
  const origin = originHeader || `${fallbackProtocol}://${host}`;
  let rpID = host.split(":")[0];
  try {
    rpID = new URL(origin).hostname;
  } catch {}
  return { rpName: "GeoAttend", rpID, origin };
}

function challengeKey(purpose, email) {
  return `${purpose}:${String(email || "").trim().toLowerCase()}`;
}

function serializeWebAuthnCredential(credential, extras = {}) {
  if (!credential) return null;
  return {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString("base64url"),
    counter: Number(credential.counter || 0),
    transports: credential.transports || [],
    ...extras
  };
}

function deserializeWebAuthnCredential(credential) {
  if (!credential?.id || !credential?.publicKey) return null;
  return {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey, "base64url"),
    counter: Number(credential.counter || 0),
    transports: credential.transports || []
  };
}

async function findStudentRowByIdentifier(identifier) {
  const raw = String(identifier || "").trim();
  const email = raw.toLowerCase();
  const regNumber = normalizeRegNumber(raw);
  return dbGet("SELECT * FROM students WHERE email = ? COLLATE NOCASE OR reg_number = ? COLLATE NOCASE LIMIT 1", [email, regNumber]);
}

async function loadBiometricProfileByEmail(email) {
  const normalized = String(email || "").trim().toLowerCase();
  const profileId = crypto.createHash("sha256").update(normalized).digest("hex");
  const row = await dbGet("SELECT profile_json FROM biometric_profiles WHERE profile_id = ? OR email = ?", [profileId, normalized]);
  return parseJsonColumn(row?.profile_json, null);
}

async function saveBiometricProfileObject(profile) {
  const email = String(profile.email || "").trim().toLowerCase();
  const profileId = crypto.createHash("sha256").update(email).digest("hex");
  const savedAt = new Date().toISOString();
  const savedProfile = { ...profile, email, profileId, savedAt };
  await dbRun(`INSERT INTO biometric_profiles (profile_id, email, profile_json, saved_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(profile_id) DO UPDATE SET
      email = excluded.email,
      profile_json = excluded.profile_json,
      saved_at = excluded.saved_at`, [profileId, email, JSON.stringify(savedProfile), savedAt]);
  const profiles = readJsonFile(BIOMETRIC_PROFILES_FILE, {});
  profiles[profileId] = savedProfile;
  writeLocalJson(BIOMETRIC_PROFILES_FILE, profiles);
  return { profileId, savedAt, savedProfile };
}

async function getWebAuthnRegistrationOptions(req, res, body) {
  const row = await findStudentRowByIdentifier(body.email || body.regNumber);
  if (!row) {
    json(res, 404, { error: "No student account was found. Please register first." });
    return;
  }
  const { rpName, rpID, origin } = getWebAuthnContext(req);
  const email = String(row.email || "").trim().toLowerCase();
  const existingProfile = await loadBiometricProfileByEmail(email);
  const existingCredential = existingProfile?.webauthnCredential;
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: email,
    userDisplayName: row.full_name || email,
    userID: Buffer.from(String(row.id || email)),
    attestationType: "none",
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required"
    },
    excludeCredentials: existingCredential?.id ? [{ id: existingCredential.id, transports: existingCredential.transports || [] }] : []
  });
  webAuthnChallengeStore.set(challengeKey("register", email), {
    challenge: options.challenge,
    rpID,
    origin,
    expiresAt: Date.now() + 5 * 60 * 1000
  });
  json(res, 200, { ok: true, options, email });
}

async function verifyWebAuthnRegistration(req, res, body) {
  const row = await findStudentRowByIdentifier(body.email || body.regNumber);
  if (!row) {
    json(res, 404, { error: "No student account was found. Please register first." });
    return;
  }
  const email = String(row.email || "").trim().toLowerCase();
  const saved = webAuthnChallengeStore.get(challengeKey("register", email));
  if (!saved || saved.expiresAt < Date.now()) {
    webAuthnChallengeStore.delete(challengeKey("register", email));
    json(res, 400, { error: "Device security request expired. Try again." });
    return;
  }
  const verification = await verifyRegistrationResponse({
    response: body.response,
    expectedChallenge: saved.challenge,
    expectedOrigin: saved.origin,
    expectedRPID: saved.rpID,
    requireUserVerification: true
  });
  if (!verification.verified || !verification.registrationInfo?.credential) {
    json(res, 401, { error: "Device security verification failed." });
    return;
  }
  webAuthnChallengeStore.delete(challengeKey("register", email));
  const credential = serializeWebAuthnCredential(verification.registrationInfo.credential, {
    credentialDeviceType: verification.registrationInfo.credentialDeviceType,
    credentialBackedUp: verification.registrationInfo.credentialBackedUp
  });
  json(res, 200, { ok: true, email, credential, method: "biometric" });
}

async function getWebAuthnLoginOptions(req, res, body) {
  const row = await findStudentRowByIdentifier(body.email || body.regNumber);
  if (!row) {
    json(res, 404, { error: "No student account was found. Please register first." });
    return;
  }
  const email = String(row.email || "").trim().toLowerCase();
  const profile = await loadBiometricProfileByEmail(email);
  const credential = profile?.webauthnCredential;
  if (!credential?.id) {
    json(res, 409, { error: "No registered fingerprint security is enrolled for this student. Complete identity verification first." });
    return;
  }
  const { rpID, origin } = getWebAuthnContext(req);
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{ id: credential.id, transports: credential.transports || [] }],
    userVerification: "required"
  });
  webAuthnChallengeStore.set(challengeKey("login", email), {
    challenge: options.challenge,
    rpID,
    origin,
    expiresAt: Date.now() + 5 * 60 * 1000,
    purpose: body.purpose === "attendance" ? "attendance" : "login",
    sessionId: String(body.sessionId || "").trim()
  });
  json(res, 200, { ok: true, options, email });
}

async function verifyWebAuthnLogin(req, res, body) {
  const row = await findStudentRowByIdentifier(body.email || body.regNumber);
  if (!row) {
    json(res, 404, { error: "No student account was found. Please register first." });
    return;
  }
  const email = String(row.email || "").trim().toLowerCase();
  const saved = webAuthnChallengeStore.get(challengeKey("login", email));
  if (!saved || saved.expiresAt < Date.now()) {
    webAuthnChallengeStore.delete(challengeKey("login", email));
    json(res, 400, { error: "Login security request expired. Try again." });
    return;
  }
  const profile = await loadBiometricProfileByEmail(email);
  const storedCredential = deserializeWebAuthnCredential(profile?.webauthnCredential);
  if (!storedCredential) {
    json(res, 409, { error: "No registered fingerprint security is enrolled for this student." });
    return;
  }
  const verification = await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: saved.challenge,
    expectedOrigin: saved.origin,
    expectedRPID: saved.rpID,
    credential: storedCredential,
    requireUserVerification: true
  });
  if (!verification.verified) {
    json(res, 401, { error: "Device security login failed." });
    return;
  }
  webAuthnChallengeStore.delete(challengeKey("login", email));
  profile.webauthnCredential.counter = verification.authenticationInfo.newCounter;
  await saveBiometricProfileObject(profile);
  let checkinToken = null;
  if (saved.purpose === "attendance" && saved.sessionId) {
    checkinToken = crypto.randomBytes(32).toString("base64url");
    attendanceAuthorizationStore.set(checkinToken, { email, sessionId: saved.sessionId, expiresAt: Date.now() + 2 * 60 * 1000 });
  }
  json(res, 200, { ok: true, user: sqliteStudentFromRow(row), method: "fingerprint", checkinToken });
}
async function saveBiometricProfile(res, profile) {
  if (!profile || !isEmail(profile.email)) {
    json(res, 400, { error: "A valid profile email is required." });
    return;
  }

  const hasSecurity = Boolean(profile?.biometric?.platformAuthenticator || profile?.webauthnCredential || profile?.platformCredential?.webauthnCredential);
  if (!hasSecurity) {
    json(res, 400, { error: "Complete one login security method before saving." });
    return;
  }

  const email = profile.email.trim().toLowerCase();
  const normalizedProfile = {
    ...profile,
    email,
    webauthnCredential: profile.webauthnCredential || profile.platformCredential?.webauthnCredential || null
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
  autoFinalizeExpiredSessions();
  const { items: sessions, source } = await readLiveSessionsStore();
  const activeSessions = sessions
    .filter((session) => session && session.status === "active")
    .sort((a, b) => new Date(b.createdAt || b.updatedAt || 0) - new Date(a.createdAt || a.updatedAt || 0));
  const visibleSessions = await filterSessionsForRequest(req, activeSessions);

  json(res, 200, {
    ok: true,
    source,
    sessions: visibleSessions,
    activeSession: visibleSessions[0] || null
  });
}

function distanceBetweenCoordinatesMeters(first, second) {
  const lat1 = Number(first?.lat);
  const lng1 = Number(first?.lng);
  const lat2 = Number(second?.lat);
  const lng2 = Number(second?.lng);
  if (![lat1, lng1, lat2, lng2].every(Number.isFinite)) return Number.NaN;
  const radians = (value) => value * Math.PI / 180;
  const earthRadiusMeters = 6371000;
  const deltaLat = radians(lat2 - lat1);
  const deltaLng = radians(lng2 - lng1);
  const haversine = Math.sin(deltaLat / 2) ** 2
    + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(deltaLng / 2) ** 2;
  return 2 * earthRadiusMeters * Math.asin(Math.sqrt(haversine));
}

function readFreshStudentLocation(position) {
  const lat = Number(position?.lat);
  const lng = Number(position?.lng);
  const accuracy = Number(position?.accuracy);
  const timestamp = new Date(position?.timestamp || 0).getTime();
  if (![lat, lng, accuracy, timestamp].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
    return { ok: false, error: "A current GPS location is required before checking in." };
  }
  if (accuracy <= 0 || accuracy > STUDENT_GPS_MAX_ACCURACY_METERS) {
    return { ok: false, error: `Phone GPS accuracy must be ${STUDENT_GPS_MAX_ACCURACY_METERS}m or better. Current accuracy: ${Math.round(accuracy)}m.` };
  }
  const ageMs = Math.abs(Date.now() - timestamp);
  if (ageMs > STUDENT_GPS_MAX_AGE_MS) {
    return { ok: false, error: "Your GPS reading is older than 15 seconds. Wait for a fresh location and try again." };
  }
  return { ok: true, location: { lat, lng, accuracy, timestamp }, ageMs };
}

function validateSessionGeofence(geofence) {
  const lat = Number(geofence?.lat);
  const lng = Number(geofence?.lng);
  const radius = Number(geofence?.radius);
  if (![lat, lng, radius].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
    return { ok: false, error: "This session does not have a valid GPS geofence." };
  }
  if (radius < MIN_GEOFENCE_RADIUS_METERS || radius > MAX_GEOFENCE_RADIUS_METERS) {
    return { ok: false, error: `Session radius must be between ${MIN_GEOFENCE_RADIUS_METERS}m and ${MAX_GEOFENCE_RADIUS_METERS}m.` };
  }
  return { ok: true, geofence: { lat, lng, radius, accuracy: Number(geofence.accuracy || 0), source: geofence.source || "manual" } };
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

  const geofenceCheck = validateSessionGeofence(session.geofence);
  if (!geofenceCheck.ok) {
    json(res, 400, { error: geofenceCheck.error });
    return;
  }
  if (String(session.geofence?.source || "").includes("geolocation") && geofenceCheck.geofence.accuracy > ADMIN_GEOFENCE_MAX_ACCURACY_METERS) {
    json(res, 400, { error: `Admin GPS accuracy must be ${ADMIN_GEOFENCE_MAX_ACCURACY_METERS}m or better before creating a live geofence.` });
    return;
  }

  const { items: sessions } = await readLiveSessionsStore();
  const actorAdmin = findAdminByIdentifier(session.actorEmail || session.createdBy || "");
  const scopedSession = applyAdminScopeToSession(session, actorAdmin);
  if (actorAdmin && isLecturerAdmin(actorAdmin)) {
    const assignedCodes = await getLecturerAssignedCourseCodes(actorAdmin.email);
    if (!assignedCodes.includes(getCourseCode(scopedSession.course))) {
      json(res, 403, { error: "You can only create sessions for courses assigned to your Lecturer Admin account." });
      return;
    }
  }
  const normalizedSession = {
    ...scopedSession,
    id,
    status: "active",
    geofence: {
      ...scopedSession.geofence,
      ...geofenceCheck.geofence,
      capturedAt: scopedSession.geofence?.capturedAt || scopedSession.geofence?.timestamp || new Date().toISOString()
    },
    updatedAt: new Date().toISOString()
  };
  const nextSessions = [
    normalizedSession,
    ...sessions.filter((item) => item && item.id !== id)
  ].slice(0, 50);
  const { source } = await writeLiveSessionsStore(nextSessions);

  json(res, 200, { ok: true, source, session: normalizedSession, sessions: nextSessions.filter((item) => item.status === "active") });
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
  if (endedSession) saveAttendanceReportFile({ ...endedSession, status: "ended", endedAt, updatedAt: endedAt }, "manual-end");
  json(res, 200, { ok: true, source, sessions: nextSessions.filter((session) => session && session.status === "active") });
}

async function getAttendance(req, res) {
  autoFinalizeExpiredSessions();
  const url = new URL(req.url, "http://127.0.0.1");
  const sessionId = String(url.searchParams.get("sessionId") || "").trim();
  const { items, source } = await readAttendanceStore();
  const principal = getRequestPrincipal(req);
  const lecturerCourseCodes = principal.admin && isLecturerAdmin(principal.admin)
    ? new Set(await getLecturerAssignedCourseCodes(principal.admin.email))
    : null;
  const attendance = items
    .filter((entry) => entry && (!sessionId || entry.sessionId === sessionId))
    .filter((entry) => {
      if (lecturerCourseCodes) return lecturerCourseCodes.has(getCourseCode(entry.course));
      if (principal.admin) return entityMatchesScope(entry, principal.admin, principal.admin.adminRole || principal.admin.role);
      if (principal.studentEmail) return String(entry.email || "").trim().toLowerCase() === principal.studentEmail;
      return true;
    })
    .sort((a, b) => new Date(b.checkedInAt || 0) - new Date(a.checkedInAt || 0));

  json(res, 200, { ok: true, source, attendance });
}

function getAttendancePdfPayload(sessionId) {
  const sessions = readJsonFile(LIVE_SESSIONS_FILE, []);
  const session = sessions.find((item) => item && item.id === sessionId) || null;
  const attendance = readJsonFile(ATTENDANCE_LOG_FILE, [])
    .filter((entry) => entry && (!sessionId || entry.sessionId === sessionId))
    .sort((a, b) => new Date(a.checkedInAt || 0) - new Date(b.checkedInAt || 0));
  const title = session?.course || attendance[0]?.course || (sessionId ? "Session Attendance Report" : "Attendance Report");
  const fileSafeTitle = title.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "attendance-report";
  const pdf = createAttendancePdf({ title, session, sessionId, attendance });

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
  const { pdf, filename } = getAttendancePdfPayload(sessionId);

  res.writeHead(200, {
    ...getCorsHeaders(),
    "Content-Type": "application/pdf",
    "Content-Disposition": `attachment; filename="${filename}"`,
    "Content-Length": pdf.length
  });
  res.end(pdf);
}

async function getAttendanceReports(req, res) {
  autoFinalizeExpiredSessions();
  const reports = readJsonFile(ATTENDANCE_REPORTS_INDEX_FILE, [])
    .filter((report) => report && report.id && report.filename)
    .sort((a, b) => new Date(b.createdAt || b.updatedAt || 0) - new Date(a.createdAt || a.updatedAt || 0));
  const visibleReports = await filterReportsForRequest(req, reports);
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

function autoFinalizeExpiredSessions() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const sessions = readJsonFile(LIVE_SESSIONS_FILE, []);
  const now = new Date();
  let changed = false;
  const nextSessions = sessions.map((session) => {
    if (!session || session.status !== "active") return session;
    const endDate = getSessionEndDate(session);
    if (!endDate || endDate > now) return session;
    changed = true;
    const endedSession = {
      ...session,
      status: "ended",
      endedAt: endDate.toISOString(),
      updatedAt: now.toISOString()
    };
    saveAttendanceReportFile(endedSession, "auto-end");
    return endedSession;
  });

  if (changed) {
    fs.writeFileSync(LIVE_SESSIONS_FILE, JSON.stringify(nextSessions, null, 2));
  }
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
    sessionId: session.id,
    title: payload.title,
    updatedAt: now
  };
  writeSavedReportPdf(report, payload);
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
    session: data.session,
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
  const geofenceCheck = validateSessionGeofence(session.geofence);
  if (!geofenceCheck.ok) {
    json(res, 403, { error: geofenceCheck.error });
    return;
  }
  const locationCheck = readFreshStudentLocation(record.position);
  if (!locationCheck.ok) {
    json(res, 403, { error: locationCheck.error });
    return;
  }
  const distanceMeters = distanceBetweenCoordinatesMeters(locationCheck.location, geofenceCheck.geofence);
  if (!Number.isFinite(distanceMeters) || distanceMeters > geofenceCheck.geofence.radius) {
    const distanceLabel = Number.isFinite(distanceMeters) ? `${Math.round(distanceMeters)}m` : "an unknown distance";
    json(res, 403, { error: `You are ${distanceLabel} from the class location. You must be within the ${Math.round(geofenceCheck.geofence.radius)}m session radius.` });
    return;
  }
  const start = getSessionStartDate(session);
  if (start && Date.now() < start.getTime()) {
    json(res, 403, { error: `Check-in has not started yet. It opens at ${start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.` });
    return;
  }

  const { items: attendance } = await readAttendanceStore();
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
  const checkinToken = String(record.checkinToken || "");
  const authorization = attendanceAuthorizationStore.get(checkinToken);
  if (!authorization || authorization.expiresAt < Date.now() || authorization.email !== email || authorization.sessionId !== sessionId) {
    json(res, 403, { error: "Verify your own registered fingerprint immediately before checking in." });
    return;
  }

  const alreadyCheckedIn = attendance.some((entry) => entry && entry.sessionId === sessionId && (
    (regNumber !== "--" && normalizeRegNumber(entry.regNumber) === regNumber)
    || String(entry.email || "").trim().toLowerCase() === email
  ));
  if (alreadyCheckedIn) {
    json(res, 409, { error: "You have already checked in for this session." });
    return;
  }

  if (!email || (!isEmail(email) && !email.endsWith("@reg.geoattend.local"))) {
    json(res, 400, { error: "Attendance requires a valid student registration number." });
    return;
  }

  const checkedInAt = record.checkedInAt || new Date().toISOString();
  const idKey = regNumber !== "--" ? `${sessionId}:${regNumber}` : `${sessionId}:${email}`;
  const id = record.id || crypto.createHash("sha256").update(idKey).digest("hex");
  const normalizedRecord = {
    ...record,
    id,
    email,
    sessionId,
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
    status: record.status || "present",
    gpsVerification: {
      distanceMeters: Math.round(distanceMeters),
      radiusMeters: Math.round(geofenceCheck.geofence.radius),
      accuracyMeters: Math.round(locationCheck.location.accuracy),
      locationAgeMs: locationCheck.ageMs,
      verifiedAt: new Date().toISOString()
    },
    checkedInAt,
    savedAt: new Date().toISOString()
  };
  delete normalizedRecord.checkinToken;
  const nextAttendance = [
    normalizedRecord,
    ...attendance.filter((entry) => {
      if (!entry || entry.id === id) return false;
      if (entry.sessionId !== sessionId) return true;
      const entryReg = normalizeRegNumber(entry.regNumber || entry.targetRegNumber);
      if (entryReg && regNumber !== "--") return entryReg !== regNumber;
      return String(entry.email || "").toLowerCase() !== email;
    })
  ].slice(0, 2000);

  const { source } = await writeAttendanceStore(nextAttendance);
  attendanceAuthorizationStore.delete(checkinToken);
  json(res, 200, { ok: true, source, record: normalizedRecord, attendance: nextAttendance });
}

function normalizeAdminRole(value) {
  const raw = String(value || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (["owner", "overall", "overall_admin", "super_admin"].includes(raw)) return "overall_admin";
  if (["faculty", "faculty_admin"].includes(raw)) return "faculty_admin";
  if (["level", "level_admin"].includes(raw)) return "level_admin";
  if (["lecturer", "lecturer_admin", "lectureradmin"].includes(raw)) return "lecturer_admin";
  return "department_admin";
}

function getRoleLabel(role) {
  return {
    overall_admin: "Overall Admin",
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
  const gps = body.gps && typeof body.gps === "object" ? {
    lat: Number(body.gps.lat),
    lng: Number(body.gps.lng),
    accuracy: Number(body.gps.accuracy || 0),
    capturedAt: body.gps.capturedAt || null
  } : null;
  const ipLocation = body.ipLocation && typeof body.ipLocation === "object" ? {
    ip: body.ipLocation.ip || null,
    city: body.ipLocation.city || null,
    region: body.ipLocation.region || null,
    country: body.ipLocation.country || body.ipLocation.country_name || null,
    lat: body.ipLocation.latitude || body.ipLocation.lat || null,
    lng: body.ipLocation.longitude || body.ipLocation.lng || null,
    source: body.ipLocation.source || "ip-lookup"
  } : null;

  const audit = {
    id: `admin-audit-${Date.now()}`,
    email,
    loginTime: new Date().toISOString(),
    gpsStatus: body.gpsStatus || (gps ? "captured" : "not-captured"),
    gps,
    ipAddress: getClientIp(req),
    ipLocation,
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
  const rows = attendance.length ? attendance : [];
  const rowsPerPage = 31;
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

function createAttendanceTemplatePage({ course, date, pageRows, startIndex, pageIndex }) {
  const tableX = 54;
  const tableY = 520;
  const tableWidth = 487;
  const rowHeight = 18;
  const colSn = 55;
  const colName = 245;
  const colReg = 105;
  const colSignature = tableWidth - colSn - colName - colReg;
  const commands = [];

  pdfText(commands, "UNIVERSITY OF UYO", 297, 780, 15, "F2", "center");
  pdfText(commands, "FACULTY OF ENGINEERING", 297, 750, 15, "F2", "center");
  pdfText(commands, "DEPARTMENT OF ELECTRICAL/ELECTRONICS ENGINEERING 2025/2026", 297, 720, 13, "F2", "center");
  pdfText(commands, "CLASS ATTENDANCE", 297, 690, 15, "F2", "center");
  pdfTextBox(commands, `COURSE: ${course}`, tableX, 640, 330, 12, "F2", "left");
  pdfTextBox(commands, `DATE: ${date}`, tableX + tableWidth - 150, 640, 150, 12, "F2", "right");

  const totalRows = Math.max(pageRows.length, 1) + 1;
  pdfRect(commands, tableX, tableY - totalRows * rowHeight, tableWidth, totalRows * rowHeight);
  for (let index = 1; index <= totalRows; index += 1) {
    const y = tableY - index * rowHeight;
    pdfLine(commands, tableX, y, tableX + tableWidth, y);
  }
  pdfLine(commands, tableX + colSn, tableY, tableX + colSn, tableY - totalRows * rowHeight);
  pdfLine(commands, tableX + colSn + colName, tableY, tableX + colSn + colName, tableY - totalRows * rowHeight);
  pdfLine(commands, tableX + colSn + colName + colReg, tableY, tableX + colSn + colName + colReg, tableY - totalRows * rowHeight);

  pdfText(commands, "S/N", tableX + 8, tableY - 13, 11, "F2");
  pdfText(commands, "NAME", tableX + colSn + 8, tableY - 13, 11, "F2");
  pdfText(commands, "REG NO", tableX + colSn + colName + 8, tableY - 13, 11, "F2");
  pdfText(commands, "SIGNATURE", tableX + colSn + colName + colReg + 8, tableY - 13, 10, "F2");

  if (!pageRows.length) {
    pdfText(commands, "No checked-in students for this session yet.", tableX + colSn + 8, tableY - rowHeight - 13, 10, "F1");
  } else {
    pageRows.forEach((record, index) => {
      const rowY = tableY - (index + 1) * rowHeight - 13;
      pdfText(commands, String(startIndex + index + 1).padStart(3, "0"), tableX + 8, rowY, 10, "F1");
      pdfText(commands, truncateForPdf(String(record.fullName || record.email || "Unknown Student").toUpperCase(), 32), tableX + colSn + 8, rowY, 10, "F1");
      pdfText(commands, truncateForPdf(String(record.regNumber || "--").toUpperCase(), 18), tableX + colSn + colName + 8, rowY, 10, "F1");
      drawPdfSignature(commands, record, tableX + colSn + colName + colReg + 6, tableY - (index + 2) * rowHeight + 3, colSignature - 12, rowHeight - 6);
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
  const base = session.createdAt ? new Date(session.createdAt) : new Date();
  if (Number.isNaN(base.getTime())) return null;
  const start = new Date(base);
  start.setHours(hours, minutes, 0, 0);
  return start;
}

function getSessionEndDate(session) {
  if (!session?.endTime) return null;
  const start = getSessionStartDate(session);
  if (!start) return null;
  const [hours, minutes] = String(session.endTime).split(":").map(Number);
  if (!Number.isFinite(hours) || !Number.isFinite(minutes)) return null;
  const end = new Date(start);
  end.setHours(hours, minutes, 0, 0);
  if (end <= start) end.setDate(end.getDate() + 1);
  return end;
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
