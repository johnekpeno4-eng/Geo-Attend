"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const calibrationFile = path.join(__dirname, "..", "data", "calibration.csv");
const calibrationColumns = ["timestamp", "student_id", "best_match_score", "sharpest_frame_score", "passed"];

function createFingerprintCheckin(deps) {
  const { dbRun, dbGet, dbAll, ensureColumn, readLiveSessionsStore, writeAttendanceStore, json, verifyAdminCredentials } = deps;
  const threshold = Number(process.env.FINGERPRINT_SCORE_THRESHOLD || 40);
  const matcherUrl = (process.env.FINGERPRINT_MATCHER_URL || "http://127.0.0.1:5512").replace(/\/$/, "");
  const failedAttempts = new Map();

  async function initialize() {
    await dbRun("CREATE TABLE IF NOT EXISTS fingerprint_templates (student_id TEXT PRIMARY KEY REFERENCES students(id) ON DELETE CASCADE, ciphertext BLOB NOT NULL, iv BLOB NOT NULL, auth_tag BLOB NOT NULL, created_at TEXT NOT NULL)");
    await dbRun("CREATE TABLE IF NOT EXISTS checkin_challenges (id TEXT PRIMARY KEY, challenge_hash TEXT NOT NULL, student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE, session_id TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at TEXT)");
    await dbRun("CREATE INDEX IF NOT EXISTS idx_checkin_challenges_student_session ON checkin_challenges(student_id,session_id,expires_at)");
    await ensureColumn("attendance", "student_id", "TEXT");
    await ensureColumn("attendance", "match_score", "REAL");
    await ensureColumn("attendance", "ip", "TEXT");
    await ensureColumn("attendance", "timestamp", "TEXT");
    await ensureColumn("attendance", "method", "TEXT NOT NULL DEFAULT 'manual'");
    await dbRun("UPDATE attendance SET method = 'manual' WHERE method IS NULL OR method = ''");
    await dbRun("CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_student_session_unique ON attendance(session_id,student_id) WHERE student_id IS NOT NULL");
  }

  function tokenValid(value) {
    const expected = process.env.CHECKIN_HOTSPOT_TOKEN || "";
    if (expected.length < 16 || typeof value !== "string") return false;
    const hash = (text) => crypto.createHash("sha256").update(text).digest();
    return crypto.timingSafeEqual(hash(expected), hash(value)) && expected.length === value.length;
  }
  function key() {
    const value = Buffer.from(process.env.FINGERPRINT_TEMPLATE_KEY || "", "base64");
    if (value.length !== 32) throw new Error("Fingerprint encryption key is not configured.");
    return value;
  }
  function encrypt(templates) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(templates), "utf8"), cipher.final()]);
    return { data, iv, tag: cipher.getAuthTag() };
  }
  function decrypt(row) {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key(), Buffer.from(row.iv));
    decipher.setAuthTag(Buffer.from(row.auth_tag));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(row.ciphertext)), decipher.final()]).toString("utf8"));
  }
  function clientIp(req) { return String(req.socket && req.socket.remoteAddress || "").slice(0, 64); }
  function isOpen(session, now) {
    if (!session || session.status !== "active") return false;
    const base = session.date || new Date(session.createdAt || Date.now()).toISOString().slice(0, 10);
    const parse = (time) => /^\d{2}:\d{2}$/.test(String(time || "")) ? new Date(base + "T" + time + ":00") : null;
    const start = parse(session.checkInStartTime || session.attendanceStart || session.startTime);
    const end = parse(session.checkInEndTime || session.attendanceEnd || session.endTime || session.sessionEndTime);
    if (!start || !end || Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return false;
    if (end <= start) end.setDate(end.getDate() + 1);
    return now >= start && now <= end;
  }
  async function sessionById(id) {
    const store = await readLiveSessionsStore();
    return store.items.find((item) => String(item && item.id) === String(id)) || null;
  }
  function attemptKey(studentId, sessionId) { return `${studentId}:${sessionId}`; }
  function attemptCount(studentId, sessionId) { return failedAttempts.get(attemptKey(studentId, sessionId)) || 0; }
  function clearSessionAttempts(sessionId) {
    const suffix = `:${sessionId}`;
    for (const key of failedAttempts.keys()) if (key.endsWith(suffix)) failedAttempts.delete(key);
  }
  async function fail(req, res, studentId, sessionId, reason, code, message, countAttempt = true) {
    if (countAttempt && studentId && sessionId) failedAttempts.set(attemptKey(studentId, sessionId), attemptCount(studentId, sessionId) + 1);
    return json(res, code, { error: message });
  }
  async function matcher(path, payload) {
    const token = process.env.FINGERPRINT_MATCHER_TOKEN || "";
    if (token.length < 32) throw new Error("Matcher token is not configured.");
    const response = await fetch(matcherUrl + path, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + token }, body: JSON.stringify(payload), signal: AbortSignal.timeout(20000) });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "Matcher unavailable.");
    return result;
  }
  function frames(body) {
    if (!Array.isArray(body.frames) || body.frames.length !== 8 || body.frames.some((x) => typeof x !== "string" || x.length > 1800000)) {
      if (Array.isArray(body.frames)) body.frames.fill("");
      throw new Error("Capture exactly eight fingertip frames and retry.");
    }
    const captured = body.frames.map((x) => x.replace(/^data:image\/jpeg;base64,/, ""));
    body.frames.fill("");
    return captured;
  }

  async function challenge(req, res, body) {
    const sessionId = String(body.session_id || "");
    let studentId = String(body.student_id || "");
    if (!sessionId) return json(res, 400, { error: "Student and session are required." });
    if (!tokenValid(body.hotspot_token)) return json(res, 403, { error: "The lecturer's hotspot token is invalid. Ask for the current token." });
    const student = studentId
      ? await dbGet("SELECT id FROM students WHERE id = ?", [studentId])
      : await dbGet("SELECT id FROM students WHERE email = ? COLLATE NOCASE", [String(body.email || "").trim()]);
    if (!student) return json(res, 404, { error: "Student account not found. Ask the lecturer to confirm your registration." });
    studentId = student.id;
    const session = await sessionById(sessionId);
    if (!isOpen(session, new Date())) { clearSessionAttempts(sessionId); return json(res, 403, { error: "This class is outside its check-in window. Ask the lecturer if you are present." }); }
    if (await dbGet("SELECT id FROM attendance WHERE session_id = ? AND student_id = ? LIMIT 1", [sessionId, studentId])) return json(res, 409, { error: "You already checked in for this session." });
    if (attemptCount(studentId, sessionId) >= 3) return json(res, 429, { error: "You have used three scan attempts. Ask the lecturer to record your attendance." });
    const raw = crypto.randomBytes(32).toString("base64url"), id = crypto.randomUUID();
    await dbRun("INSERT INTO checkin_challenges(id,challenge_hash,student_id,session_id,expires_at) VALUES(?,?,?,?,?)", [id, crypto.createHash("sha256").update(raw).digest("hex"), studentId, sessionId, Date.now() + 30000]);
    return json(res, 201, { challenge_id: id, challenge: raw, student_id: studentId, expires_in: 30 });
  }

  async function scan(req, res, body) {
    if (process.env.FP_CALIBRATION !== "1") return scanAttempt(req, res, body, null);
    const sample = {
      timestamp: new Date().toISOString(),
      studentId: String(body.student_id || ""),
      bestMatchScore: "",
      sharpestFrameScore: "",
      passed: false
    };
    try {
      return await scanAttempt(req, res, body, sample);
    } finally {
      try {
        fs.mkdirSync(path.dirname(calibrationFile), { recursive: true });
        if (!fs.existsSync(calibrationFile)) fs.writeFileSync(calibrationFile, calibrationColumns.join(",") + "\n", { flag: "wx" });
        const values = [sample.timestamp, sample.studentId, sample.bestMatchScore, sample.sharpestFrameScore, sample.passed ? "true" : "false"];
        const csv = values.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(",") + "\n";
        fs.appendFileSync(calibrationFile, csv, "utf8");
      } catch (error) {
        console.error("Fingerprint calibration log could not be written:", error.message);
      }
    }
  }

  async function scanAttempt(req, res, body, calibration) {
    const studentId = String(body.student_id || ""), sessionId = String(body.session_id || ""), challengeId = String(body.challenge_id || "");
    const savedChallenge = await dbGet("SELECT * FROM checkin_challenges WHERE id = ?", [challengeId]);
    const claimed = savedChallenge && !savedChallenge.used_at
      ? await dbRun("UPDATE checkin_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL", [new Date().toISOString(), challengeId])
      : { changes: 0 };
    const rejected = (code, message, reason, countAttempt = true) => fail(req, res, studentId, sessionId, reason, code, message, countAttempt);
    if (!savedChallenge || savedChallenge.used_at || claimed.changes !== 1 || savedChallenge.expires_at < Date.now() || savedChallenge.student_id !== studentId || savedChallenge.session_id !== sessionId) {
      if (savedChallenge) failedAttempts.set(attemptKey(savedChallenge.student_id, savedChallenge.session_id), attemptCount(savedChallenge.student_id, savedChallenge.session_id) + 1);
      return rejected(400, "Scan expired or was already used. Tap Check In and scan again.", "challenge-invalid", false);
    }
    const providedHash = crypto.createHash("sha256").update(String(body.challenge || "")).digest();
    if (savedChallenge.challenge_hash.length !== 64 || !crypto.timingSafeEqual(Buffer.from(savedChallenge.challenge_hash, "hex"), providedHash)) return rejected(400, "Scan request did not match. Tap Check In and retry.", "challenge-mismatch");
    if (attemptCount(studentId, sessionId) >= 3) return rejected(429, "You have used three scan attempts. Ask the lecturer to record your attendance.", "rate-limit", false);
    if (!tokenValid(body.hotspot_token)) return rejected(403, "The lecturer's hotspot token is invalid. Ask for the current token.", "hotspot-token-invalid");
    const student = await dbGet("SELECT id,email,reg_number,full_name FROM students WHERE id = ?", [studentId]);
    if (!student) return rejected(404, "Student account not found. Ask the lecturer.", "student-not-found");
    const session = await sessionById(sessionId);
    if (!isOpen(session, new Date())) return rejected(403, "This class is outside its check-in window. Ask the lecturer if you are present.", "outside-window");
    if (await dbGet("SELECT id FROM attendance WHERE session_id = ? AND student_id = ? LIMIT 1", [sessionId, studentId])) return rejected(409, "Attendance is already recorded for this session.", "duplicate-checkin");
    let captured;
    try { captured = frames(body); } catch (error) { return rejected(400, error.message, "invalid-frames"); }
    const templatesRow = await dbGet("SELECT ciphertext,iv,auth_tag FROM fingerprint_templates WHERE student_id = ?", [studentId]);
    if (!templatesRow) { captured.fill(""); return rejected(409, "Camera fingerprint is not enrolled. Ask the lecturer to enroll it.", "template-missing"); }
    let candidates = [];
    try {
      candidates = decrypt(templatesRow);
      const result = await matcher("/v1/match", { frames: captured, templates: candidates });
      captured.fill("");
      const score = Number(result.score);
      if (calibration) {
        calibration.bestMatchScore = Number.isFinite(score) ? score : "";
        const sharpest = Number(result.sharpestFrameScore);
        calibration.sharpestFrameScore = Number.isFinite(sharpest) ? sharpest : "";
      }
      if (!Number.isFinite(score) || score < Number(process.env.FINGERPRINT_SCORE_THRESHOLD || 40)) return rejected(401, "Fingerprint did not match. Clean the camera, steady your finger, and retry.", "fingerprint-mismatch");
      const checkedInAt = new Date().toISOString();
      const record = { id: crypto.randomUUID(), studentId, sessionId, email: student.email, regNumber: student.reg_number, fullName: student.full_name, course: session.course || "Class", status: "incomplete", checkedInAt, timestamp: checkedInAt, checkedOutAt: null, matchScore: score, ip: clientIp(req), method: "camera", savedAt: checkedInAt };
      const all = (await dbAll("SELECT attendance_json FROM attendance ORDER BY datetime(checked_in_at) DESC")).map((r) => { try { return JSON.parse(r.attendance_json); } catch { return null; } }).filter(Boolean);
      await writeAttendanceStore([record, ...all]);
      failedAttempts.delete(attemptKey(studentId, sessionId));
      if (calibration) calibration.passed = true;
      return json(res, 200, { ok: true, record: { id: record.id, sessionId, checkedInAt, matchScore: score, status: record.status } });
    } catch (error) {
      captured.fill("");
      if (error && String(error.code || "").startsWith("SQLITE_CONSTRAINT")) return rejected(409, "You already checked in for this session.", "duplicate-checkin");
      return rejected(503, "Fingerprint verification is unavailable. Retry; if it continues, ask the lecturer.", "matcher-error");
    } finally {
      captured.fill("");
      candidates.fill("");
    }
  }

  async function enroll(req, res, body) {
    if (!verifyAdminCredentials(String(body.actorEmail || ""), String(body.adminPassword || ""))) return json(res, 403, { error: "Enter a valid admin password to enroll a fingerprint." });
    const studentId = String(body.student_id || "");
    if (!await dbGet("SELECT id FROM students WHERE id = ?", [studentId])) return json(res, 404, { error: "Student account not found." });
    let captured;
    try { captured = frames(body); } catch (error) { return json(res, 400, { error: error.message }); }
    try {
      const extracted = await matcher("/v1/extract", { frames: captured });
      if (!Array.isArray(extracted.templates) || extracted.templates.length < 3) return json(res, 422, { error: "Not enough clear fingerprint detail. Retake the enrollment scan." });
      const encrypted = encrypt(extracted.templates);
      await dbRun("INSERT INTO fingerprint_templates(student_id,ciphertext,iv,auth_tag,created_at) VALUES(?,?,?,?,?) ON CONFLICT(student_id) DO UPDATE SET ciphertext=excluded.ciphertext,iv=excluded.iv,auth_tag=excluded.auth_tag,created_at=excluded.created_at", [studentId, encrypted.data, encrypted.iv, encrypted.tag, new Date().toISOString()]);
      return json(res, 200, { ok: true, student_id: studentId, template_count: extracted.templates.length });
    } catch { return json(res, 503, { error: "Fingerprint enrollment unavailable. Retry or contact support." }); }
  }

  return { initialize, challenge, scan, enroll, clearSessionAttempts };
}

module.exports = { createFingerprintCheckin };
