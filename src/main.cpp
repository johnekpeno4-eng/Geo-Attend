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
#include <mbedtls/md.h>
#include "device_config.h"

#if !defined(DEVICE_ID) || !defined(DEVICE_API_KEY) || !defined(DEVICE_TOKEN_SECRET) || !defined(SERVER_BASE_URL)
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
String activeSessionId;
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
  screen("SAVED OFFLINE", "will upload later");
  return true;
}

bool sendAttendance(uint16_t slot, const String& sessionId, const String& timestamp, bool allowQueue) {
  JsonDocument event;
  event["espId"] = DEVICE_ID; event["sessionId"] = sessionId; event["slotId"] = slot; event["timestamp"] = timestamp;
  String payload; serializeJson(event, payload);
  String response;
  int code = httpRequest("POST", "/api/device/checkin", payload, response);
    if (code == 200 || code == 201 || code == 400 || code == 403 || code == 404) {
    JsonDocument result;
      if (deserializeJson(result, response) == DeserializationError::Ok) {
        String status = result["status"] | "rejected";
        if ((code == 400 || code == 403 || code == 404) && status == "rejected") continue;
      if (status == "accepted") { screen("PRESENT", String((const char*)result["student"]["name"] | "")); feedback(1); return true; }
      if (status == "duplicate") { screen("ALREADY IN", "duplicate scan"); feedback(2); return true; }
      screen("REJECTED", result["reason"] | "not accepted"); feedback(3); return true;
    }
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
      if (deserializeJson(result, response) == DeserializationError::Ok && (String((const char*)result["status"] | "") == "accepted" || String((const char*)result["status"] | "") == "duplicate" || String((const char*)result["status"] | "") == "rejected")) continue;
    }
    blocked = true; output.println(line);
  }
  input.close(); output.flush(); output.close(); LittleFS.remove("/queue.jsonl"); LittleFS.rename("/queue.tmp", "/queue.jsonl");
}

void updateSession() {
  String response;
  int code = httpRequest("GET", apiPath("/api/device/session"), "", response);
  if (code <= 0 || code >= 300) { WiFi.setAutoReconnect(true); return; }
  JsonDocument result;
  if (deserializeJson(result, response) != DeserializationError::Ok) return;
  JsonVariant session = result["session"];
  activeSessionId = session.isNull() ? "" : String((const char*)session["id"] | "");
  File file = LittleFS.open("/session.txt", "w"); if (file) { file.print(activeSessionId); file.close(); }
  if (activeSessionId.length()) screen("READY", String((const char*)session["course"] | "Attendance open"));
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

void serveToken() {
  if (!activeSessionId.length()) { phoneServer.send(409, "application/json", "{\"error\":\"No attendance session\"}"); return; }
  const time_t now = time(nullptr);
  if (now < 1700000000) { phoneServer.send(503, "application/json", "{\"error\":\"Device clock is not synchronized\"}"); return; }
  const uint32_t timeSlot = static_cast<uint32_t>(now / 30);
  const String message = activeSessionId + "|" + String(timeSlot);
  uint8_t mac[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, reinterpret_cast<const unsigned char*>(DEVICE_TOKEN_SECRET), strlen(DEVICE_TOKEN_SECRET), reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), mac);
  char token[9];
  snprintf(token, sizeof(token), "%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3]);
  JsonDocument out; out["sessionId"] = activeSessionId; out["token"] = token; out["timeSlot"] = timeSlot;
  String encoded; serializeJson(out, encoded); phoneServer.send(200, "application/json", encoded);
}

const char PHONE_PAGE[] PROGMEM = R"HTML(
<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><title>UUY Attendance</title>
<style>body{font:16px system-ui;max-width:34rem;margin:2rem auto;padding:0 1rem;color:#10213b}input,button{box-sizing:border-box;width:100%;padding:.8rem;margin:.35rem 0;border-radius:.6rem;border:1px solid #bbc5d4}button{background:#0759bd;color:#fff;font-weight:700}small{color:#555}#msg{padding:.75rem;background:#eff5ff;border-radius:.5rem}</style>
<h1>Lecture attendance</h1><p>Bind this phone once using your student account. Connect to the attendance Wi-Fi while checking in.</p>
<label>Student email<input id="email" type="email" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label>
<button id="bind">Bind this phone</button><button id="checkin">Check in to active lecture</button><p id="msg" role="status">Connect to the lecture device Wi-Fi.</p>
<script>
const deviceId=localStorage.phoneDeviceId||(localStorage.phoneDeviceId="phone-"+Array.from(crypto.getRandomValues(new Uint8Array(12)),x=>x.toString(16).padStart(2,"0")).join(""));
const msg=document.querySelector("#msg"),email=document.querySelector("#email"),password=document.querySelector("#password");
async function post(path,data){const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.error||"Request failed");return j}
document.querySelector("#bind").onclick=async()=>{try{msg.textContent="Binding phone…";const r=await post("/bind",{email:email.value,password:password.value,deviceId});password.value="";msg.textContent=r.message}catch(e){msg.textContent=e.message}};
document.querySelector("#checkin").onclick=async()=>{try{if(!email.value)throw Error("Enter your student email first.");msg.textContent="Checking in…";const token=await(await fetch("/token")).json();if(!token.token)throw Error(token.error||"No active session");const r=await post("/checkin",{email:email.value,deviceId,...token});msg.textContent=r.status==="accepted"?"Attendance recorded for "+(r.student?.name||email.value):r.status==="duplicate"?"You are already checked in.":r.reason||"Check-in rejected."}catch(e){msg.textContent=e.message}};
</script></html>)HTML";

void proxyPhoneBind() {
  JsonDocument body;
  if (deserializeJson(body, phoneServer.arg("plain")) != DeserializationError::Ok) { phoneServer.send(400, "application/json", "{\"error\":\"Invalid request\"}"); return; }
  body["espId"] = DEVICE_ID;
  String payload, response; serializeJson(body, payload);
  int code = httpRequest("POST", "/api/student-device/bind", payload, response);
  phoneServer.send(code > 0 ? code : 503, "application/json", response.length() ? response : "{\"error\":\"Attendance server unavailable\"}");
}

void proxyPhoneCheckin() {
  JsonDocument body;
  if (deserializeJson(body, phoneServer.arg("plain")) != DeserializationError::Ok) { phoneServer.send(400, "application/json", "{\"error\":\"Invalid request\"}"); return; }
  body["espId"] = DEVICE_ID;
  String payload, response; serializeJson(body, payload);
  int code = httpRequest("POST", "/api/device/phone-checkin", payload, response);
  phoneServer.send(code > 0 ? code : 503, "application/json", response.length() ? response : "{\"error\":\"Attendance server unavailable\"}");
}

void setup() {
  Serial.begin(115200);
  pinMode(BUZZER_PIN, OUTPUT); pinMode(GREEN_LED_PIN, OUTPUT); pinMode(RED_LED_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW); digitalWrite(GREEN_LED_PIN, LOW); digitalWrite(RED_LED_PIN, HIGH);
  LittleFS.begin();
  sensorSerial.begin(SENSOR_BAUD); finger.begin(SENSOR_BAUD); sensorReady = finger.verifyPassword();
  if (USE_OLED) { Wire.begin(12, 14); displayReady = display.begin(SSD1306_SWITCHCAPVCC, 0x3C); }
  if (USE_RTC && rtc.begin()) { rtcReady = true; if (rtc.lostPower()) rtc.adjust(DateTime(F(__DATE__), F(__TIME__))); }
  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(ROUTER_SSID, ROUTER_PASSWORD);
  // In ESP8266 AP+STA mode the AP must share the station radio channel; the SDK moves the AP to the router's channel after STA association.
  WiFi.softAP(STUDENT_AP_SSID, STUDENT_AP_PASSWORD, 1, false, 4);
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  File session = LittleFS.open("/session.txt", "r"); if (session) { activeSessionId = session.readString(); activeSessionId.trim(); session.close(); }
  phoneServer.on("/token", HTTP_GET, serveToken);
  phoneServer.on("/", HTTP_GET, []() { phoneServer.send_P(200, "text/html; charset=utf-8", PHONE_PAGE); });
  phoneServer.on("/bind", HTTP_POST, proxyPhoneBind);
  phoneServer.on("/checkin", HTTP_POST, proxyPhoneCheckin);
  phoneServer.begin();
  screen(sensorReady ? "STARTING" : "SENSOR ERROR", WiFi.localIP().toString());
}

void loop() {
  phoneServer.handleClient();
  if (WiFi.status() == WL_CONNECTED && millis() - lastPollAt >= POLL_MS) { lastPollAt = millis(); updateSession(); }
  pollEnrollment();
  pollCommands();
  stepEnrollment();
  matchFinger();
  uploadQueue();
  yield();
}
