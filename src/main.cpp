// Keep the root .ino as the single source of truth while allowing PlatformIO
// to compile it as the project's Arduino entry point.
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

#include "../geoattend_survey_device.ino"
