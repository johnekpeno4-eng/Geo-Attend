/*
  GeoAttend Survey Device
  ESP-12F (ESP8266) + u-blox NEO-M8N GPS + SSD1306 OLED + 1 button

  Button:   tap = capture corner (10 s average)
            hold 1.5-5 s = finish survey
            hold 5 s+    = setup mode (Wi-Fi AP "GeoAttend-Survey", open 192.168.4.1)

  Libraries (Arduino Library Manager):
    Adafruit SSD1306, Adafruit GFX, TinyGPSPlus (Mikal Hart), ArduinoJson (v7)
  Board: esp8266 core -> "NodeMCU 1.0 (ESP-12E Module)" or "LOLIN(WEMOS) D1 mini"
  Flash size: 4MB (FS:1MB ...)  (LittleFS is used)

  Wiring (NodeMCU / D1 mini labels):
    OLED SDA -> D2, SCL -> D1, VCC 3.3V, GND
    Button   -> D3 (GPIO0) to GND  (NodeMCU: the onboard FLASH button already works)
    GPS mode A (GPS_USE_HW_UART 0, bring-up / USB debug):  GPS TX -> D5, GPS RX -> D6
    GPS mode B (GPS_USE_HW_UART 1, recommended for RTK):   GPS TX -> D7, GPS RX -> D8
    GPS VCC + GND shared. Do not hold the button while pressing reset/upload.
*/

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>
#include <SoftwareSerial.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <TinyGPSPlus.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <base64.h>
#include <Wire.h>

// ---------------- Hardware settings ----------------
#define GPS_USE_HW_UART 0        // 0 = SoftwareSerial D5/D6 (Serial = USB debug), 1 = UART0 swapped to D7/D8 (debug on Serial1/GPIO2)
#define GPS_BAUD 9600            // NEO-M8N default; change if the receiver UART was reconfigured
const uint8_t BTN_PIN = 0;       // D3 / GPIO0
const uint8_t GPS_RX_PIN = 14;   // D5  (GPS TX goes here)  - SoftwareSerial mode only
const uint8_t GPS_TX_PIN = 12;   // D6  (GPS RX goes here)  - SoftwareSerial mode only

#if GPS_USE_HW_UART
  #define GPS_PORT Serial
  #define DBG Serial1
#else
  SoftwareSerial gpsSerial(GPS_RX_PIN, GPS_TX_PIN);
  #define GPS_PORT gpsSerial
  #define DBG Serial
#endif

// ---------------- Capture rules ----------------
const uint32_t CAPTURE_MS = 10000;
const int   MIN_SATS = 6;
const float MAX_HDOP = 2.5;
const int   MIN_GOOD = 6;              // minimum good fixes during the 10 s window
const float MAX_SPREAD_RTK_M = 0.15;   // max wander while averaging (RTK mode)
const float MAX_SPREAD_GPS_M = 5.0;    // max wander when RTK is not required

// ---------------- Files ----------------
const char* CONFIG_FILE = "/config.json";
const char* STATE_FILE  = "/state.json";
const char* QUEUE_FILE  = "/queue.jsonl";
const char* QUEUE_TMP   = "/queue.tmp";

// ---------------- Config ----------------
struct Config {
  String wifiSsid, wifiPass, serverUrl, deviceToken;
  String ntripHost, ntripMount, ntripUser, ntripPass;
  uint16_t ntripPort = 2101;
  bool requireRtk = false;       // NEO-M8N standalone GPS is accepted unless RTK is explicitly enabled
} cfg;

// ---------------- Globals ----------------
TinyGPSPlus gps;
TinyGPSCustom fqGN(gps, "GNGGA", 6), fqGP(gps, "GPGGA", 6);
TinyGPSCustom gstLatGN(gps, "GNGST", 6), gstLonGN(gps, "GNGST", 7);
TinyGPSCustom gstLatGP(gps, "GPGST", 6), gstLonGP(gps, "GPGST", 7);

Adafruit_SSD1306 display(128, 64, &Wire, -1);
bool displayOk = false;

ESP8266WebServer web(80);
bool setupMode = false;

WiFiClient ntrip;
bool ntripConnected = false;
uint32_t ntripLastData = 0, ntripLastTry = 0, lastGgaSent = 0;

char nmeaBuf[128];
uint8_t nmeaLen = 0;
String lastGGA;
uint32_t ggaCount = 0;

bool wifiOk = false, serverOk = false, capturing = false;
bool surveyActive = false;
uint32_t surveyId = 0, seq = 0, finishedId = 0;
String surveyName;
int serverPoints = 0;
int queued = 0;

String toastText;
uint32_t toastUntil = 0;
uint32_t lastPoll = 0, lastDrawMs = 0;

// ---------------- Helpers ----------------
void toast(const String& msg, uint32_t ms = 3000) {
  toastText = msg;
  toastUntil = millis() + ms;
  DBG.println(msg);
}

const char* fixName(int q) {
  switch (q) {
    case 0: return "NO_FIX";
    case 1: return "GPS";
    case 2: return "DGPS";
    case 4: return "RTK_FIXED";
    case 5: return "RTK_FLOAT";
    default: return "OTHER";
  }
}

int fixQuality() {
  uint32_t aGN = fqGN.isValid() ? fqGN.age() : 0xFFFFFFFF;
  uint32_t aGP = fqGP.isValid() ? fqGP.age() : 0xFFFFFFFF;
  uint32_t a = (aGN < aGP) ? aGN : aGP;
  if (a > 3000) return 0;
  return atoi(aGN <= aGP ? fqGN.value() : fqGP.value());
}

// Estimated horizontal accuracy (m) from GST sentence, or -1 if GST is not enabled on the receiver
float estAccuracyM() {
  uint32_t aGN = gstLatGN.isValid() ? gstLatGN.age() : 0xFFFFFFFF;
  uint32_t aGP = gstLatGP.isValid() ? gstLatGP.age() : 0xFFFFFFFF;
  uint32_t a = (aGN < aGP) ? aGN : aGP;
  if (a > 3000) return -1;
  float la, lo;
  if (aGN <= aGP) { la = atof(gstLatGN.value()); lo = atof(gstLonGN.value()); }
  else            { la = atof(gstLatGP.value()); lo = atof(gstLonGP.value()); }
  return sqrtf(la * la + lo * lo);
}

void utcString(char* out, size_t n) {
  if (gps.date.isValid() && gps.time.isValid()) {
    snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02dZ", gps.date.year(), gps.date.month(),
             gps.date.day(), gps.time.hour(), gps.time.minute(), gps.time.second());
  } else {
    out[0] = 0;
  }
}

bool ntripOk() { return ntripConnected && (millis() - ntripLastData < 8000); }

String baseUrl() {
  String u = cfg.serverUrl;
  u.trim();
  while (u.endsWith("/")) u.remove(u.length() - 1);
  return u;
}

// ---------------- Storage ----------------
bool loadConfig() {
  File f = LittleFS.open(CONFIG_FILE, "r");
  if (!f) return false;
  JsonDocument doc;
  DeserializationError e = deserializeJson(doc, f);
  f.close();
  if (e) return false;
  cfg.wifiSsid    = String((const char*)(doc["wifiSsid"] | ""));
  cfg.wifiPass    = String((const char*)(doc["wifiPass"] | ""));
  cfg.serverUrl   = String((const char*)(doc["serverUrl"] | ""));
  cfg.deviceToken = String((const char*)(doc["deviceToken"] | ""));
  cfg.ntripHost   = String((const char*)(doc["ntripHost"] | ""));
  cfg.ntripMount  = String((const char*)(doc["ntripMount"] | ""));
  cfg.ntripUser   = String((const char*)(doc["ntripUser"] | ""));
  cfg.ntripPass   = String((const char*)(doc["ntripPass"] | ""));
  cfg.ntripPort   = doc["ntripPort"] | 2101;
  cfg.requireRtk  = doc["requireRtk"] | false;
  return true;
}

bool saveConfig() {
  JsonDocument doc;
  doc["wifiSsid"] = cfg.wifiSsid;
  doc["wifiPass"] = cfg.wifiPass;
  doc["serverUrl"] = cfg.serverUrl;
  doc["deviceToken"] = cfg.deviceToken;
  doc["ntripHost"] = cfg.ntripHost;
  doc["ntripMount"] = cfg.ntripMount;
  doc["ntripUser"] = cfg.ntripUser;
  doc["ntripPass"] = cfg.ntripPass;
  doc["ntripPort"] = cfg.ntripPort;
  doc["requireRtk"] = cfg.requireRtk;
  File f = LittleFS.open(CONFIG_FILE, "w");
  if (!f) return false;
  serializeJson(doc, f);
  f.close();
  return true;
}

void loadState() {
  File f = LittleFS.open(STATE_FILE, "r");
  if (!f) return;
  JsonDocument doc;
  if (!deserializeJson(doc, f)) {
    surveyId = doc["surveyId"] | 0;
    seq = doc["seq"] | 0;
    finishedId = doc["finishedId"] | 0;
    surveyActive = (surveyId != 0 && surveyId != finishedId);  // last known survey, until the server says otherwise
  }
  f.close();
}

void saveState() {
  JsonDocument doc;
  doc["surveyId"] = surveyId;
  doc["seq"] = seq;
  doc["finishedId"] = finishedId;
  File f = LittleFS.open(STATE_FILE, "w");
  if (!f) return;
  serializeJson(doc, f);
  f.close();
}

void queueAppend(char kind, const char* body) {
  File f = LittleFS.open(QUEUE_FILE, "a");
  if (!f) { toast("Flash write failed"); return; }
  f.print(kind);
  f.print('|');
  f.println(body);
  f.close();
  queued++;
}

void countQueue() {
  queued = 0;
  File f = LittleFS.open(QUEUE_FILE, "r");
  if (!f) return;
  while (f.available()) {
    String l = f.readStringUntil('\n');
    l.trim();
    if (l.length() > 2) queued++;
  }
  f.close();
}

// ---------------- GPS ----------------
void pumpGps() {
  int budget = 512;
  while (GPS_PORT.available() && budget-- > 0) {
    char c = (char)GPS_PORT.read();
    gps.encode(c);
    if (c == '$') nmeaLen = 0;
    if (nmeaLen < sizeof(nmeaBuf) - 1) nmeaBuf[nmeaLen++] = c;
    if (c == '\n') {
      nmeaBuf[nmeaLen] = 0;
      if (strncmp(nmeaBuf, "$GNGGA", 6) == 0 || strncmp(nmeaBuf, "$GPGGA", 6) == 0) {
        lastGGA = String(nmeaBuf);
        lastGGA.trim();
        ggaCount++;
      }
      nmeaLen = 0;
    }
  }
}

// ---------------- NTRIP (RTK corrections) ----------------
void ntripEnsure() {
  if (ntripConnected || cfg.ntripHost.length() == 0 || !wifiOk) return;
  if (millis() - ntripLastTry < 8000) return;
  ntripLastTry = millis();
  ntrip.stop();
  ntrip.setTimeout(3000);
  if (!ntrip.connect(cfg.ntripHost.c_str(), cfg.ntripPort)) { DBG.println("NTRIP connect failed"); return; }

  String auth = base64::encode(cfg.ntripUser + ":" + cfg.ntripPass, false);
  String req = "GET /" + cfg.ntripMount + " HTTP/1.0\r\n";
  req += "User-Agent: NTRIP GeoAttendSurvey/1.0\r\n";
  req += "Authorization: Basic " + auth + "\r\n";
  req += "Accept: */*\r\nConnection: close\r\n\r\n";
  ntrip.print(req);

  uint32_t t = millis();
  while (!ntrip.available() && millis() - t < 6000) { delay(10); yield(); }
  String status = ntrip.readStringUntil('\n');
  status.trim();
  if (status.indexOf("SOURCETABLE") >= 0) { toast("NTRIP: wrong mountpoint"); ntrip.stop(); return; }
  if (status.indexOf("401") >= 0)         { toast("NTRIP: bad login"); ntrip.stop(); return; }
  if (status.indexOf("200") < 0)          { toast("NTRIP: " + status.substring(0, 16)); ntrip.stop(); return; }
  if (status.startsWith("HTTP/")) {       // skip HTTP headers until the blank line
    uint32_t th = millis();
    while (millis() - th < 3000) {
      String h = ntrip.readStringUntil('\n');
      h.trim();
      if (h.length() == 0) break;
    }
  }
  ntripConnected = true;
  ntripLastData = millis();
  lastGgaSent = 0;
  DBG.println("NTRIP connected");
}

void pumpNtrip() {
  if (!ntripConnected) return;
  if (!ntrip.connected() && ntrip.available() == 0) { ntripConnected = false; return; }
  uint8_t buf[128];
  int budget = 512;
  int n;
  while (budget > 0 && (n = ntrip.available()) > 0) {
    n = ntrip.read(buf, n > (int)sizeof(buf) ? sizeof(buf) : n);
    if (n <= 0) break;
    GPS_PORT.write(buf, n);
    ntripLastData = millis();
    budget -= n;
  }
  // Some casters (VRS networks) need our position; send GGA every 10 s
  if (millis() - lastGgaSent > 10000 && lastGGA.length() > 20 && fixQuality() > 0) {
    ntrip.print(lastGGA);
    ntrip.print("\r\n");
    lastGgaSent = millis();
  }
  if (millis() - ntripLastData > 20000) { ntrip.stop(); ntripConnected = false; }
}

// ---------------- Server API ----------------
bool apiCall(bool isPost, const String& path, const String& body, JsonDocument& resp, int& status) {
  String url = baseUrl() + path;
  HTTPClient http;
  WiFiClient plain;
  WiFiClientSecure secure;
  if (url.startsWith("https://")) {
    secure.setInsecure();               // no certificate check (see notes)
    secure.setBufferSizes(1024, 512);
    if (!http.begin(secure, url)) return false;
  } else {
    if (!http.begin(plain, url)) return false;
  }
  http.setTimeout(8000);
  http.addHeader("X-Device-Token", cfg.deviceToken);
  http.addHeader("Content-Type", "application/json");
  status = isPost ? http.POST(body) : http.GET();
  if (status > 0) {
    String payload = http.getString();
    deserializeJson(resp, payload);
  }
  http.end();
  return status > 0;
}

void pollActiveSurvey() {
  JsonDocument r;
  int st = 0;
  if (!apiCall(false, "/api/survey/active", "", r, st)) { serverOk = false; return; }
  if (st == 401 || st == 403) { serverOk = false; toast("Token rejected by server"); return; }
  if (st != 200) { serverOk = false; return; }
  serverOk = true;
  bool active = r["active"] | false;
  uint32_t id = r["survey_id"] | 0;
  if (active && id != 0 && id != finishedId) {
    if (id != surveyId) { surveyId = id; seq = 0; saveState(); }
    surveyName = String((const char*)(r["building_name"] | "Survey"));
    serverPoints = r["points_count"] | 0;
    surveyActive = true;
  } else {
    surveyActive = false;
  }
}

// return 1 = sent, 0 = retry later, -1 = rejected (dropped)
int sendRecord(const String& line, String& err) {
  if (line.length() < 3 || line[1] != '|') return -1;
  char kind = line[0];
  String body = line.substring(2);
  String path = (kind == 'p') ? "/api/survey/point" : "/api/survey/finish";
  JsonDocument r;
  int st = 0;
  if (!apiCall(true, path, body, r, st)) { serverOk = false; return 0; }
  if (st >= 200 && st < 300) {
    serverOk = true;
    if (r["ok"].is<bool>() && !r["ok"].as<bool>()) {
      err = String((const char*)(r["error"] | "Rejected"));
      return -1;
    }
    if (kind == 'p') serverPoints = r["points_count"] | serverPoints;
    return 1;
  }
  if (st == 401 || st == 403) { err = "Device not authorised"; serverOk = false; return 0; }
  if (st == 400 || st == 404 || st == 409 || st == 410 || st == 422) {
    err = String((const char*)(r["error"] | "Rejected"));
    return -1;
  }
  return 0;
}

void flushQueue() {
  if (!wifiOk || queued == 0) return;
  File f = LittleFS.open(QUEUE_FILE, "r");
  if (!f) { queued = 0; return; }
  File t = LittleFS.open(QUEUE_TMP, "w");
  if (!t) { f.close(); return; }
  bool stop = false;
  int kept = 0;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() < 3) continue;
    if (stop) { t.println(line); kept++; continue; }
    String err;
    int res = sendRecord(line, err);
    if (res == 1) {
      // sent
    } else if (res == -1) {
      toast("Server: " + err, 5000);
    } else {
      stop = true;
      t.println(line);
      kept++;
    }
    pumpGps();
    if (wifiOk) pumpNtrip();
    yield();
  }
  f.close();
  t.close();
  LittleFS.remove(QUEUE_FILE);
  if (kept > 0) LittleFS.rename(QUEUE_TMP, QUEUE_FILE);
  else LittleFS.remove(QUEUE_TMP);
  queued = kept;
}

// ---------------- Display ----------------
void drawUI() {
  if (!displayOk) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  if (setupMode) {
    display.println(F("SETUP MODE"));
    display.println(F("WiFi: GeoAttend-Survey"));
    display.println(F("Pass: survey1234"));
    display.println(F("Open 192.168.4.1"));
    display.display();
    return;
  }
  if (surveyActive) {
    String n = surveyName.length() ? surveyName : String("Survey #") + surveyId;
    if (n.length() > 21) n = n.substring(0, 21);
    display.print(n);
  } else {
    display.print(F("No active survey"));
  }
  int q = fixQuality();
  int sats = gps.satellites.isValid() ? (int)gps.satellites.value() : 0;
  float h = gps.hdop.isValid() ? (float)gps.hdop.hdop() : 99.9;
  display.setCursor(0, 10);
  display.printf("%s S%d H%.1f", fixName(q), sats, h);
  display.setCursor(0, 20);
  float acc = estAccuracyM();
  if (acc >= 0) display.printf("Acc: %.3f m", acc);
  else display.print(F("Acc: n/a"));
  display.setCursor(0, 30);
  display.printf("W:%s SV:%s NT:%s", wifiOk ? "OK" : "--", serverOk ? "OK" : "--", ntripOk() ? "OK" : "--");
  display.setCursor(0, 40);
  display.printf("Corners:%lu Queue:%d", (unsigned long)seq, queued);
  display.setCursor(0, 54);
  if (millis() < toastUntil) display.print(toastText.substring(0, 21));
  else display.print(F("Tap=cap Hold=finish"));
  display.display();
}

void drawCapture(uint32_t elapsed, int good, int bad, int q) {
  if (!displayOk) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print(F("CAPTURING - HOLD STILL"));
  display.setCursor(0, 14);
  display.printf("%s good:%d bad:%d", fixName(q), good, bad);
  display.drawRect(0, 34, 128, 10, SSD1306_WHITE);
  display.fillRect(2, 36, (int)((124UL * elapsed) / CAPTURE_MS), 6, SSD1306_WHITE);
  display.setCursor(0, 50);
  display.printf("%lus / %lus", (unsigned long)(elapsed / 1000), (unsigned long)(CAPTURE_MS / 1000));
  display.display();
}

// ---------------- Survey actions ----------------
void captureCorner() {
  if (!surveyActive) { toast("No active survey"); return; }
  static double sLat[40], sLng[40];
  int good = 0, bad = 0, minSats = 99, lastGoodQ = 0, accN = 0;
  float worstHdop = 0;
  double accSum = 0;
  uint32_t start = millis(), lastDraw = 0, lastGga = ggaCount;
  capturing = true;

  while (millis() - start < CAPTURE_MS) {
    pumpGps();
    if (wifiOk) { ntripEnsure(); pumpNtrip(); }
    if (ggaCount != lastGga) {
      lastGga = ggaCount;
      int q = fixQuality();
      int sats = gps.satellites.isValid() ? (int)gps.satellites.value() : 0;
      float h = gps.hdop.isValid() ? (float)gps.hdop.hdop() : 99.0;
      bool ok = gps.location.isValid() && gps.location.age() < 1500 && q > 0 &&
                sats >= MIN_SATS && h <= MAX_HDOP && (!cfg.requireRtk || q == 4);
      if (ok) {
        if (good < 40) {
          sLat[good] = gps.location.lat();
          sLng[good] = gps.location.lng();
          good++;
          if (h > worstHdop) worstHdop = h;
          if (sats < minSats) minSats = sats;
          lastGoodQ = q;
          float a = estAccuracyM();
          if (a >= 0) { accSum += a; accN++; }
        }
      } else {
        bad++;
      }
    }
    if (millis() - lastDraw > 250) { lastDraw = millis(); drawCapture(millis() - start, good, bad, fixQuality()); }
    yield();
  }
  capturing = false;

  if (good < MIN_GOOD || bad > 1) {
    toast(String("Weak fix ") + good + "/" + bad + ", retry", 4000);
    return;
  }

  double mLat = 0, mLng = 0;
  for (int i = 0; i < good; i++) { mLat += sLat[i]; mLng += sLng[i]; }
  mLat /= good;
  mLng /= good;
  double cosLat = cos(mLat * DEG_TO_RAD), maxDev = 0;
  for (int i = 0; i < good; i++) {
    double dy = (sLat[i] - mLat) * 111320.0;
    double dx = (sLng[i] - mLng) * 111320.0 * cosLat;
    double d = sqrt(dx * dx + dy * dy);
    if (d > maxDev) maxDev = d;
  }
  float limit = cfg.requireRtk ? MAX_SPREAD_RTK_M : MAX_SPREAD_GPS_M;
  if (maxDev > limit) {
    toast(String("Moved ") + String(maxDev, 2) + "m, retry", 4000);
    return;
  }

  char ts[24];
  utcString(ts, sizeof(ts));
  char acc[16];
  if (accN > 0) snprintf(acc, sizeof(acc), "%.3f", accSum / accN);
  else strcpy(acc, "null");

  char body[420];
  snprintf(body, sizeof(body),
           "{\"survey_id\":%lu,\"seq\":%lu,\"lat\":%.8f,\"lng\":%.8f,\"hdop\":%.2f,\"sats\":%d,"
           "\"fix_type\":\"%s\",\"fix_quality\":%d,\"acc_h_m\":%s,\"samples\":%d,\"spread_m\":%.3f,"
           "\"captured_at\":\"%s\",\"device_id\":\"esp-%06X\"}",
           (unsigned long)surveyId, (unsigned long)(seq + 1), mLat, mLng, worstHdop, minSats,
           fixName(lastGoodQ), lastGoodQ, acc, good, maxDev, ts, (unsigned)ESP.getChipId());

  queueAppend('p', body);
  seq++;
  saveState();
  if (wifiOk && serverOk) flushQueue();
  toast(String("Corner #") + seq + (queued > 0 ? " saved (queued)" : " sent"), 4000);
}

void finishSurvey() {
  if (!surveyActive) { toast("No active survey"); return; }
  if (seq < 3) { toast("Need 3+ corners"); return; }
  char body[96];
  snprintf(body, sizeof(body), "{\"survey_id\":%lu,\"points_sent\":%lu}", (unsigned long)surveyId, (unsigned long)seq);
  queueAppend('f', body);
  finishedId = surveyId;
  surveyActive = false;
  seq = 0;
  saveState();
  toast("Survey finished", 4000);
  if (wifiOk) flushQueue();
}

// ---------------- Setup portal ----------------
String esc(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '&') o += "&amp;";
    else if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;";
    else if (c == '"') o += "&quot;";
    else if (c == '\'') o += "&#39;";
    else o += c;
  }
  return o;
}

String inputRow(const char* name, const char* label, const String& val, const char* type = "text", const char* ph = "") {
  return String("<label>") + label + "<input name='" + name + "' type='" + type + "' value='" + esc(val) +
         "' placeholder='" + ph + "'></label>";
}

void handleRoot() {
  String h;
  h.reserve(3500);
  h += F("<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<title>GeoAttend Survey Setup</title><style>body{font-family:sans-serif;max-width:480px;margin:16px auto;padding:0 12px}"
         "label{display:block;margin:10px 0 2px;font-size:14px}input{width:100%;padding:8px;box-sizing:border-box}"
         "button{margin-top:16px;padding:12px;width:100%;font-size:16px}h3{margin-top:22px}</style></head><body>"
         "<h2>GeoAttend Survey Device</h2><form method='POST' action='/save'>");
  h += F("<h3>Wi-Fi</h3>");
  h += inputRow("wifiSsid", "SSID", cfg.wifiSsid);
  h += inputRow("wifiPass", "Password", "", "password", "(unchanged if blank)");
  h += F("<h3>Server</h3>");
  h += inputRow("serverUrl", "Server URL (https://... or http://...)", cfg.serverUrl);
  h += inputRow("deviceToken", "Device token", "", "password", "(unchanged if blank)");
  h += F("<h3>RTK corrections (NTRIP)</h3>");
  h += inputRow("ntripHost", "Host", cfg.ntripHost);
  h += inputRow("ntripPort", "Port", String(cfg.ntripPort), "number");
  h += inputRow("ntripMount", "Mountpoint", cfg.ntripMount);
  h += inputRow("ntripUser", "Username", cfg.ntripUser);
  h += inputRow("ntripPass", "Password", "", "password", "(unchanged if blank)");
  h += F("<label><input type='checkbox' name='requireRtk' style='width:auto' ");
  if (cfg.requireRtk) h += F("checked");
  h += F("> Only accept RTK Fixed corners</label><button type='submit'>Save and restart</button></form></body></html>");
  web.send(200, "text/html", h);
}

void handleSave() {
  cfg.wifiSsid = web.arg("wifiSsid");
  if (web.arg("wifiPass").length()) cfg.wifiPass = web.arg("wifiPass");
  cfg.serverUrl = web.arg("serverUrl");
  if (web.arg("deviceToken").length()) cfg.deviceToken = web.arg("deviceToken");
  cfg.ntripHost = web.arg("ntripHost");
  int p = web.arg("ntripPort").toInt();
  cfg.ntripPort = p > 0 ? p : 2101;
  cfg.ntripMount = web.arg("ntripMount");
  cfg.ntripUser = web.arg("ntripUser");
  if (web.arg("ntripPass").length()) cfg.ntripPass = web.arg("ntripPass");
  cfg.requireRtk = web.hasArg("requireRtk");
  bool ok = saveConfig();
  web.send(200, "text/html", ok ? "<h3>Saved. Restarting...</h3>" : "<h3>Save failed</h3>");
  if (ok) { delay(800); ESP.restart(); }
}

void enterSetupMode() {
  setupMode = true;
  ntrip.stop();
  ntripConnected = false;
  WiFi.disconnect();
  WiFi.mode(WIFI_AP);
  WiFi.softAP("GeoAttend-Survey", "survey1234");
  web.on("/", HTTP_GET, handleRoot);
  web.on("/save", HTTP_POST, handleSave);
  web.begin();
  DBG.println("Setup mode: connect to GeoAttend-Survey, open 192.168.4.1");
}

// ---------------- Button ----------------
void handleButton() {
  static bool down = false;
  static uint32_t t0 = 0;
  bool pressed = digitalRead(BTN_PIN) == LOW;
  uint32_t now = millis();
  if (pressed && !down) {
    down = true;
    t0 = now;
  } else if (pressed && down) {
    uint32_t held = now - t0;
    if (held >= 5000) toast("Release: SETUP MODE", 300);
    else if (held >= 1500) toast("Release: FINISH survey", 300);
    else if (held >= 80) toast("Release: capture corner", 300);
  } else if (!pressed && down) {
    down = false;
    uint32_t held = now - t0;
    if (held < 80) return;
    if (held < 1500) captureCorner();
    else if (held < 5000) finishSurvey();
    else enterSetupMode();
  }
}

// ---------------- Arduino entry points ----------------
void setup() {
  pinMode(BTN_PIN, INPUT_PULLUP);

#if GPS_USE_HW_UART
  Serial.setRxBufferSize(1024);
  Serial.begin(GPS_BAUD);
  Serial.swap();            // UART0 -> GPIO13 (RX, D7) / GPIO15 (TX, D8)
  Serial1.begin(115200);    // debug out on GPIO2 (TX only)
#else
  Serial.begin(115200);
  gpsSerial.begin(GPS_BAUD);
#endif
  delay(200);
  DBG.println("\nGeoAttend Survey Device starting");

  Wire.begin();
  displayOk = display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  if (displayOk) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.println(F("GeoAttend Survey"));
    display.println(F("Starting..."));
    display.display();
  } else {
    DBG.println("OLED not found (continuing without display)");
  }

  if (!LittleFS.begin()) {
    LittleFS.format();
    LittleFS.begin();
  }
  loadConfig();
  loadState();
  countQueue();

  bool configured = cfg.wifiSsid.length() && cfg.serverUrl.length() && cfg.deviceToken.length();
  if (!configured) {
    enterSetupMode();
    return;
  }

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPass.c_str());
}

void loop() {
  pumpGps();

  if (setupMode) {
    web.handleClient();
    if (millis() - lastDrawMs > 500) { lastDrawMs = millis(); drawUI(); }
    return;
  }

  wifiOk = (WiFi.status() == WL_CONNECTED);
  handleButton();

  if (wifiOk) {
    ntripEnsure();
    pumpNtrip();
    if (!capturing && millis() - lastPoll > 5000) {
      lastPoll = millis();
      pollActiveSurvey();
      if (serverOk && queued > 0) flushQueue();
    }
  } else {
    serverOk = false;
  }

  if (millis() - lastDrawMs > 400) { lastDrawMs = millis(); drawUI(); }
  yield();
}
