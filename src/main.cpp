#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <WiFiClientSecureBearSSL.h>
#include <SoftwareSerial.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <Adafruit_Fingerprint.h>
#include <ESP8266WebServer.h>
#include <time.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <RTClib.h>
#include "device_config.h"

#if !defined(DEVICE_ID) || !defined(DEVICE_API_KEY) || !defined(SERVER_BASE_URL)
#error "Copy include/device_config.h.example to include/device_config.h and fill in the device settings."
#endif

// R307 serial: sensor TX -> GPIO4, sensor RX -> GPIO5.
static const uint8_t SENSOR_RX_PIN = 4;
static const uint8_t SENSOR_TX_PIN = 5;
static const uint8_t BUZZER_PIN = 13;
static const uint8_t GREEN_LED_PIN = 16;
static const uint8_t RED_LED_PIN = 2;
static const size_t MAX_QUEUE_BYTES = 4096;
static const uint32_t POLL_MS = 5000;

SoftwareSerial sensorSerial(SENSOR_RX_PIN, SENSOR_TX_PIN);
Adafruit_Fingerprint finger(&sensorSerial);
ESP8266WebServer phoneServer(80);
Adafruit_SSD1306 display(128, 64, &Wire, -1);
RTC_DS3231 rtc;
bool displayReady = false, rtcReady = false, sensorReady = false;
bool rtcSyncedThisBoot = false;
bool serverReachable = false;
String activeSessionId;
String lastAttendanceMessage = "Place your finger on the reader to check in.";
String lastAttendanceState = "ready";
uint16_t lastSeenSlot = 0;
uint32_t lastPollAt = 0, lastEnrollPollAt = 0, lastQueueAt = 0, lastMatchAt = 0;
uint32_t lastCommandPollAt = 0;
String pendingEnrollmentId;
uint8_t enrollStage = 0;
uint16_t enrollSlot = 0;
uint32_t stageAt = 0;

String requestUrl(const String& path) { return String(SERVER_BASE_URL) + path; }
String epochIso() {
  time_t now = time(nullptr);
  if (now < 1700000000 && rtcReady) {
    DateTime current = rtc.now();
    now = current.unixtime();
    timeval tv = {now, 0};
    settimeofday(&tv, nullptr);
  }
  if (now < 1700000000) return "";
  struct tm utc;
  gmtime_r(&now, &utc);
  char out[25];
  strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return String(out);
}

void screen(const String& title, const String& subtitle = "") {
  Serial.println(title + (subtitle.length() ? ": " + subtitle : ""));
  if (!displayReady) return;
  display.clearDisplay(); display.setTextColor(SSD1306_WHITE); display.setTextSize(1);
  display.setCursor(0, 0); display.println("DEEP GOTECH"); display.setTextSize(2);
  display.setCursor(0, 18); display.println(title.substring(0, 14)); display.setTextSize(1);
  display.setCursor(0, 46); display.println(subtitle.substring(0, 21)); display.display();
}
void feedback(uint8_t kind) {
  // 1 accepted, 2 duplicate, 3 rejected.
  digitalWrite(GREEN_LED_PIN, kind == 1 ? HIGH : LOW);
  digitalWrite(RED_LED_PIN, kind == 3 ? LOW : HIGH);
  const uint8_t count = kind == 2 ? 2 : 1;
  for (uint8_t i = 0; i < count; ++i) {
    digitalWrite(BUZZER_PIN, HIGH); delay(kind == 3 ? 500 : 100); digitalWrite(BUZZER_PIN, LOW);
    if (i + 1 < count) delay(120);
  }
  delay(80);
  digitalWrite(GREEN_LED_PIN, LOW); digitalWrite(RED_LED_PIN, HIGH);
}

int httpRequest(const String& method, const String& path, const String& payload, String& response) {
  HTTPClient http;
  const String url = requestUrl(path);
  bool started = false;
  if (url.startsWith("https://")) {
    BearSSL::WiFiClientSecure secure;
    if (SERVER_TLS_INSECURE) secure.setInsecure();
    else { BearSSL::X509List rootCa(SERVER_ROOT_CA_PEM); secure.setTrustAnchors(&rootCa); }
    started = http.begin(secure, url);
    if (started) {
      http.addHeader("X-Device-Key", DEVICE_API_KEY);
      if (method == "POST") http.addHeader("Content-Type", "application/json");
      int status = method == "GET" ? http.GET() : http.POST(payload);
      response = status > 0 ? http.getString() : "";
      http.end(); return status;
    }
  } else {
    WiFiClient plain;
    started = http.begin(plain, url);
    if (started) {
      http.addHeader("X-Device-Key", DEVICE_API_KEY);
      if (method == "POST") http.addHeader("Content-Type", "application/json");
      int status = method == "GET" ? http.GET() : http.POST(payload);
      response = status > 0 ? http.getString() : "";
      http.end(); return status;
    }
  }
  return started ? 0 : -1;
}

String apiPath(const String& path) {
  String out = path + (path.indexOf('?') >= 0 ? "&" : "?") + "espId=" + DEVICE_ID;
  return out;
}

bool appendQueue(const String& event) {
  File current = LittleFS.open("/queue.jsonl", "r");
  size_t size = current ? current.size() : 0;
  if (current) current.close();
  if (size + event.length() + 1 > MAX_QUEUE_BYTES) { screen("QUEUE FULL", "check-in not stored"); return false; }
  File queue = LittleFS.open("/queue.jsonl", "a");
  if (!queue) return false;
  queue.println(event); queue.flush(); queue.close();
  lastAttendanceState = "queued";
  lastAttendanceMessage = "Saved on this attendance device. It will sync when internet returns.";
  screen("SAVED OFFLINE", "will upload later");
  return true;
}

bool sendAttendance(uint16_t slot, const String& sessionId, const String& timestamp, bool allowQueue) {
  JsonDocument event;
  event["espId"] = DEVICE_ID; event["sessionId"] = sessionId; event["slotId"] = slot; event["timestamp"] = timestamp;
  String payload; serializeJson(event, payload);
  String response;
  int code = httpRequest("POST", "/api/device/checkin", payload, response);
  if ((code >= 200 && code < 300) || (code >= 400 && code < 500)) {
    JsonDocument result;
    if (deserializeJson(result, response) == DeserializationError::Ok) {
      const String status = result["status"] | "rejected";
      if (status == "accepted") { lastAttendanceState = "accepted"; lastAttendanceMessage = "Attendance recorded."; screen("PRESENT", String(result["student"]["name"] | "")); feedback(1); return true; }
      if (status == "duplicate") { lastAttendanceState = "duplicate"; lastAttendanceMessage = "You are already checked in."; screen("ALREADY IN", "duplicate scan"); feedback(2); return true; }
      lastAttendanceState = "rejected"; lastAttendanceMessage = String(result["reason"] | "Check-in not accepted.");
      screen("REJECTED", lastAttendanceMessage); feedback(3); return true;
    }
    if (code >= 400 && code < 500) { screen("REJECTED", "server denied scan"); feedback(3); return true; }
  }
  if (allowQueue) return appendQueue(payload);
  return false;
}

void uploadQueue() {
  if (!WiFi.isConnected() || millis() - lastQueueAt < 8000 || !LittleFS.exists("/queue.jsonl")) return;
  lastQueueAt = millis();
  File input = LittleFS.open("/queue.jsonl", "r");
  File output = LittleFS.open("/queue.tmp", "w");
  if (!input || !output) { if (input) input.close(); if (output) output.close(); return; }
  bool blocked = false;
  while (input.available()) {
    String line = input.readStringUntil('\n'); line.trim(); if (!line.length()) continue;
    if (blocked) { output.println(line); continue; }
    JsonDocument event;
    if (deserializeJson(event, line) != DeserializationError::Ok) continue;
    String response;
    int code = httpRequest("POST", "/api/device/checkin", line, response);
    if (code == 200 || code == 201 || code == 400 || code == 403 || code == 404) {
      JsonDocument result;
      if (deserializeJson(result, response) == DeserializationError::Ok && (String(result["status"] | "") == "accepted" || String(result["status"] | "") == "duplicate" || String(result["status"] | "") == "rejected")) continue;
    }
    blocked = true; output.println(line);
  }
  input.close(); output.flush(); output.close(); LittleFS.remove("/queue.jsonl"); LittleFS.rename("/queue.tmp", "/queue.jsonl");
}

void updateSession() {
  String response;
  int code = httpRequest("GET", apiPath("/api/device/session"), "", response);
  if (code <= 0 || code >= 300) { serverReachable = false; WiFi.setAutoReconnect(true); return; }
  JsonDocument result;
  if (deserializeJson(result, response) != DeserializationError::Ok) { serverReachable = false; return; }
  serverReachable = true;
  JsonVariant session = result["session"];
  activeSessionId = session.isNull() ? "" : String(session["id"] | "");
  File file = LittleFS.open("/session.txt", "w"); if (file) { file.print(activeSessionId); file.close(); }
  if (activeSessionId.length()) screen("READY", String(session["course"] | "Attendance open"));
  else screen("NO SESSION", "wait for lecturer");
}

void pollEnrollment() {
  if (!WiFi.isConnected() || enrollStage || millis() - lastEnrollPollAt < 2500) return;
  lastEnrollPollAt = millis();
  String response;
  int code = httpRequest("GET", apiPath("/api/device/enrollment"), "", response);
  if (code < 200 || code >= 300) return;
  JsonDocument result;
  if (deserializeJson(result, response) != DeserializationError::Ok || result["enrollment"].isNull()) return;
  pendingEnrollmentId = result["enrollment"]["id"].as<String>();
  enrollSlot = result["enrollment"]["slotId"].as<uint16_t>();
  enrollStage = 1; stageAt = 0;
  screen("ENROLL", "place finger twice");
}

void pollCommands() {
  if (!WiFi.isConnected() || millis() - lastCommandPollAt < 3000) return;
  lastCommandPollAt = millis();
  String response;
  int code = httpRequest("GET", apiPath("/api/device/commands"), "", response);
  if (code < 200 || code >= 300) return;
  JsonDocument result;
  if (deserializeJson(result, response) != DeserializationError::Ok || result["command"].isNull()) return;
  JsonVariant command = result["command"];
  const String commandId = command["id"].as<String>();
  const String commandName = command["command"].as<String>();
  const uint16_t slot = command["slotId"].as<uint16_t>();
  bool ok = false;
  if (commandName == "delete-slot") {
    const uint8_t resultCode = finger.deleteModel(slot);
    ok = resultCode == FINGERPRINT_OK || resultCode == FINGERPRINT_NOTFOUND;
  }
  JsonDocument body; body["espId"] = DEVICE_ID; body["commandId"] = commandId; body["ok"] = ok;
  String payload; serializeJson(body, payload); String ignored;
  httpRequest("POST", "/api/device/commands/result", payload, ignored);
}

void postEnrollmentResult(bool ok) {
  JsonDocument body; body["espId"] = DEVICE_ID; body["enrollmentId"] = pendingEnrollmentId; body["ok"] = ok;
  String payload, response; serializeJson(body, payload);
  httpRequest("POST", "/api/device/enrollment/result", payload, response);
  screen(ok ? "ENROLLED" : "ENROLL ERROR", "slot " + String(enrollSlot));
  if (ok) feedback(1); else feedback(3);
  pendingEnrollmentId = ""; enrollSlot = 0; enrollStage = 0;
}

void stepEnrollment() {
  if (!enrollStage) return;
  uint8_t p = finger.getImage();
  if (enrollStage == 1) {
    if (p == FINGERPRINT_NOFINGER) return;
    if (p != FINGERPRINT_OK || finger.image2Tz(1) != FINGERPRINT_OK) { screen("TRY AGAIN", "finger image error"); return; }
    enrollStage = 2; stageAt = millis(); screen("REMOVE FINGER", "then touch again"); return;
  }
  if (enrollStage == 2) {
    if (p != FINGERPRINT_NOFINGER || millis() - stageAt < 700) return;
    enrollStage = 3; screen("TOUCH AGAIN", "same finger"); return;
  }
  if (enrollStage == 3) {
    if (p == FINGERPRINT_NOFINGER) return;
    if (p != FINGERPRINT_OK || finger.image2Tz(2) != FINGERPRINT_OK) { postEnrollmentResult(false); return; }
    if (finger.createModel() != FINGERPRINT_OK || finger.storeModel(enrollSlot) != FINGERPRINT_OK) { postEnrollmentResult(false); return; }
    postEnrollmentResult(true);
  }
}

void matchFinger() {
  if (!sensorReady || !activeSessionId.length() || enrollStage || millis() - lastMatchAt < 120) return;
  lastMatchAt = millis();
  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) { lastSeenSlot = 0; return; }
  if (p != FINGERPRINT_OK || finger.image2Tz() != FINGERPRINT_OK || finger.fingerFastSearch() != FINGERPRINT_OK) return;
  uint16_t slot = finger.fingerID;
  if (!slot || slot == lastSeenSlot) return;
  lastSeenSlot = slot;
  String timestamp = epochIso();
  if (!timestamp.length()) { screen("NO CLOCK", "waiting for time"); feedback(3); return; }
  screen("CHECKING", "slot " + String(slot));
  sendAttendance(slot, activeSessionId, timestamp, true);
}

size_t queuedAttendanceCount() {
  File queue = LittleFS.open("/queue.jsonl", "r");
  if (!queue) return 0;
  size_t count = 0;
  while (queue.available()) { if (queue.read() == '\n') ++count; yield(); }
  queue.close();
  return count;
}

void servePortalStatus() {
  JsonDocument status;
  status["deviceId"] = DEVICE_ID;
  status["sessionActive"] = activeSessionId.length() > 0;
  status["sessionId"] = activeSessionId;
  status["sensorReady"] = sensorReady;
  status["routerConnected"] = WiFi.isConnected();
  status["serverReachable"] = serverReachable;
  status["queuedCheckins"] = queuedAttendanceCount();
  status["lastState"] = lastAttendanceState;
  status["lastMessage"] = lastAttendanceMessage;
  String response; serializeJson(status, response);
  phoneServer.send(200, "application/json; charset=utf-8", response);
}

const char PHONE_PAGE[] PROGMEM = R"HTML(
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0759bd"><title>Class Attendance</title>
<style>
:root{font:16px system-ui,-apple-system,"Segoe UI",sans-serif;color:#10213b;background:#f3f6fb}*{box-sizing:border-box}body{max-width:38rem;margin:0 auto;padding:1rem}.card{background:#fff;border:1px solid #dce3ed;border-radius:1rem;padding:1.25rem;margin:1rem 0;box-shadow:0 3px 12px #17345b0b}h1{font-size:1.5rem;margin:.2rem 0}.muted{color:#53647d}.badge{display:inline-block;border-radius:99px;background:#edf3fc;padding:.3rem .7rem;font-size:.85rem}.steps{line-height:1.7;padding-left:1.4rem}#last{padding:.8rem;border-radius:.7rem;background:#eff5ff}.ok{color:#087443}.warn{color:#8a4b00}.offline{border-left:4px solid #e5a329}footer{text-align:center;color:#65738a;font-size:.8rem;padding:1rem}
</style></head><body>
<header class="card"><span class="badge">Local attendance network</span><h1>Class attendance</h1><p class="muted">This page is served by the classroom ESP. It works without mobile data or internet.</p></header>
<main><section class="card"><h2>Device status</h2><p id="session">Checking session…</p><p id="sensor">Checking fingerprint reader…</p><p id="internet">Checking network…</p><p><strong>Check-ins waiting to sync:</strong> <span id="queue">—</span></p></section>
<section class="card"><h2>Check in</h2><ol class="steps"><li>Stay connected to this attendance Wi-Fi.</li><li>Place your enrolled finger on the fingerprint reader attached to the ESP.</li><li>Wait for the reader’s light and sound, then check the result below.</li></ol><p id="last" role="status" aria-live="polite">Attendance updates will appear here.</p></section>
<section class="card offline"><strong>Offline attendance</strong><p class="muted">When the internet is unavailable, this device stores accepted fingerprint check-ins locally and uploads them when its internet connection returns.</p></section></main>
<footer>Device <span id="device">—</span> · This page uses no external website or CDN.</footer>
<script>
const el=id=>document.getElementById(id);async function refresh(){try{const r=await fetch('/status',{cache:'no-store'});if(!r.ok)throw Error();const s=await r.json();el('device').textContent=s.deviceId||'—';el('session').textContent=s.sessionActive?'Attendance session is active.':'No active session is currently available.';el('session').className=s.sessionActive?'ok':'warn';el('sensor').textContent=s.sensorReady?'Fingerprint reader is ready.':'Fingerprint reader is not detected.';el('sensor').className=s.sensorReady?'ok':'warn';el('internet').textContent=s.serverReachable?'Attendance server is reachable.':s.routerConnected?'Router connected; attendance server is offline.':'No router link; offline check-ins stay on this device.';el('internet').className=s.serverReachable?'':'warn';el('queue').textContent=s.queuedCheckins;el('last').textContent=s.lastMessage||'Place your enrolled finger on the reader to check in.';el('last').className=s.lastState==='rejected'?'warn':s.lastState==='accepted'?'ok':''}catch(e){el('session').textContent='Device status is temporarily unavailable. Stay connected to the attendance Wi-Fi.';el('last').textContent='This page is stored on the ESP and remains open offline.'}}refresh();setInterval(refresh,2500);
</script></body></html>)HTML";

void setup() {
  Serial.begin(115200);
  pinMode(BUZZER_PIN, OUTPUT); pinMode(GREEN_LED_PIN, OUTPUT); pinMode(RED_LED_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW); digitalWrite(GREEN_LED_PIN, LOW); digitalWrite(RED_LED_PIN, HIGH);
  LittleFS.begin();
  sensorSerial.begin(SENSOR_BAUD); finger.begin(SENSOR_BAUD); sensorReady = finger.verifyPassword();
  if (USE_OLED) { Wire.begin(12, 14); displayReady = display.begin(SSD1306_SWITCHCAPVCC, 0x3C); }
  if (USE_RTC && rtc.begin()) { rtcReady = true; if (rtc.lostPower()) screen("RTC RESET", "waiting for NTP"); }
  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(ROUTER_SSID, ROUTER_PASSWORD);
  // In ESP8266 AP+STA mode the AP must share the station radio channel; the SDK moves the AP to the router's channel after STA association.
  WiFi.softAP(STUDENT_AP_SSID, STUDENT_AP_PASSWORD, 1, false, 4);
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  File session = LittleFS.open("/session.txt", "r"); if (session) { activeSessionId = session.readString(); activeSessionId.trim(); session.close(); }
  phoneServer.on("/status", HTTP_GET, servePortalStatus);
  phoneServer.on("/", HTTP_GET, []() { phoneServer.send_P(200, "text/html; charset=utf-8", PHONE_PAGE); });
  phoneServer.begin();
  screen(sensorReady ? "STARTING" : "SENSOR ERROR", WiFi.localIP().toString());
}

void loop() {
  phoneServer.handleClient();
  const time_t clockNow = time(nullptr);
  if (rtcReady && !rtcSyncedThisBoot && clockNow > 1700000000) { rtc.adjust(DateTime(static_cast<uint32_t>(clockNow))); rtcSyncedThisBoot = true; }
  if (WiFi.status() == WL_CONNECTED && millis() - lastPollAt >= POLL_MS) { lastPollAt = millis(); updateSession(); }
  pollEnrollment();
  pollCommands();
  stepEnrollment();
  matchFinger();
  uploadQueue();
  yield();
}
