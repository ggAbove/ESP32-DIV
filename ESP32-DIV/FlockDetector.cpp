// ===================================================================
// bySaw Flock detector — find Flock Safety ALPR surveillance cameras and related
// gear (FS Ext Battery / Penguin / Pigvision). Each scan cycle does a Wi-Fi scan
// (SSID name patterns + known vendor BSSID prefixes) then a BLE scan (advertised
// name patterns). Shows id, MAC, how-detected and an RSSI bar; logs to
// /flock/flock-*.csv. SELECT exits. Signatures ported from nyanBOX (jbohack, MIT).
// ===================================================================
#include "config.h"
#include "shared.h"
#include "FlockDetector.h"
#include <WiFi.h>
#include <SD.h>
#include <string>

extern TFT_eSPI tft;
extern bool feature_active;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace FlockDetector {

struct Dev { char id[22]; char mac[18]; char how[6]; int rssi; };
static const int MAXD = 40;
static Dev s_list[MAXD];
static int s_count = 0;

static File s_csv;
static bool s_csvOpen = false;

// Wi-Fi SSID + BLE name substrings (lowercase) that flag Flock kit.
static const char *NAME_PAT[] = {"flock", "fs ext battery", "penguin", "pigvision"};
static const int NAME_PAT_N = sizeof(NAME_PAT) / sizeof(NAME_PAT[0]);
// Known Flock / FS Ext Battery vendor MAC prefixes (lowercase, "aa:bb:cc").
static const char *MAC_PFX[] = {
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84", "f0:82:c0",
    "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9", "70:c9:4e", "3c:91:80",
    "d8:f3:bc", "80:30:49", "14:5a:fc", "74:4c:a1", "08:3a:88", "9c:2f:9d",
    "94:08:53", "e4:aa:ea"};
static const int MAC_PFX_N = sizeof(MAC_PFX) / sizeof(MAC_PFX[0]);

// case-insensitive substring search
static bool containsCI(const std::string &hay, const char *needle) {
  std::string h = hay, n = needle;
  for (auto &c : h) c = tolower(c);
  return h.find(n) != std::string::npos;
}

static bool nameMatch(const std::string &s) {
  if (s.empty()) return false;
  for (int i = 0; i < NAME_PAT_N; i++)
    if (containsCI(s, NAME_PAT[i])) return true;
  return false;
}

static bool macMatch(const std::string &bssid) {
  for (int i = 0; i < MAC_PFX_N; i++)
    if (strncasecmp(bssid.c_str(), MAC_PFX[i], 8) == 0) return true;
  return false;
}

static void add(const char *id, const char *mac, const char *how, int rssi) {
  for (int i = 0; i < s_count; i++) {
    if (strcmp(s_list[i].mac, mac) == 0) { s_list[i].rssi = rssi; return; }
  }
  if (s_count < MAXD) {
    Dev &t = s_list[s_count++];
    strncpy(t.id, id, sizeof(t.id) - 1); t.id[sizeof(t.id) - 1] = 0;
    strncpy(t.mac, mac, sizeof(t.mac) - 1); t.mac[sizeof(t.mac) - 1] = 0;
    strncpy(t.how, how, sizeof(t.how) - 1); t.how[sizeof(t.how) - 1] = 0;
    t.rssi = rssi;
    if (s_csvOpen) { s_csv.printf("%s,%s,%s,%d\n", mac, how, id, rssi); s_csv.flush(); }
  }
}

static void draw(bool scanning, const char *phase) {
  tft.fillRect(0, 0, tft.width(), tft.height(), UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("Flock Detect", tft.width() / 2, 4, 1);
  tft.setTextSize(1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  char hd[44];
  snprintf(hd, sizeof(hd), "%d hits %s", s_count, scanning ? phase : "");
  tft.drawCentreString(hd, tft.width() / 2, 24, 1);

  const int rowH = 24, top = 38;
  const int rows = (tft.height() - top - 16) / rowH;
  int start = s_count > rows ? s_count - rows : 0;
  int y = top;
  for (int i = start; i < s_count; i++) {
    const Dev &t = s_list[i];
    tft.setTextColor(UI_WARN, UI_BG);
    tft.setCursor(6, y);
    char head[28];
    snprintf(head, sizeof(head), "%s [%s]", t.id, t.how);
    tft.print(head);
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.setCursor(6, y + 10);
    tft.print(t.mac);
    int pct = t.rssi + 100; if (pct < 0) pct = 0; if (pct > 60) pct = 60;
    int w = (pct * 70) / 60;
    tft.drawRect(tft.width() - 76, y + 4, 72, 8, UI_LINE);
    tft.fillRect(tft.width() - 75, y + 5, w, 6, UI_WARN);
    tft.drawFastHLine(0, y + rowH - 2, tft.width(), UI_LINE);
    y += rowH;
  }
  if (s_count == 0) {
    tft.setTextColor(UI_OK, UI_BG);
    tft.drawCentreString("no flock gear seen", tft.width() / 2, top + 20, 1);
  }
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

static void scanWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, true);
  delay(50);
  int n = WiFi.scanNetworks(false /*async*/, true /*show hidden*/);
  for (int i = 0; i < n && !feature_exit_requested && !featureExitButtonPressed(); i++) {
    std::string ssid = WiFi.SSID(i).c_str();
    std::string bssid = WiFi.BSSIDstr(i).c_str();
    if (nameMatch(ssid) || macMatch(bssid)) {
      add(ssid.empty() ? "<hidden>" : ssid.c_str(), bssid.c_str(), "WiFi", WiFi.RSSI(i));
    }
  }
  WiFi.scanDelete();
}

static void scanBLE(BLEScan *scan) {
  BLEScanResults res = scan->start(1, false);  // 1s so exit stays responsive
  for (int i = 0; i < res.getCount(); i++) {
    BLEAdvertisedDevice d = res.getDevice(i);
    std::string nm = d.getName();
    if (!nameMatch(nm)) continue;
    std::string mac = d.getAddress().toString();
    add(nm.c_str(), mac.c_str(), "BLE", d.getRSSI());
  }
  scan->clearResults();
}

void run() {
  feature_active = true;
  setTouchButtonInputEnabled(true);  // enable touch SELECT slot for touch-only exit
  feature_exit_requested = false;
  pauseBackgroundRadioTasks();
  s_count = 0;
  tft.fillScreen(UI_BG);

  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/flock");
    char path[40];
    snprintf(path, sizeof(path), "/flock/flock-%lu.csv", (unsigned long)(millis() / 1000));
    s_csv = SD.open(path, FILE_WRITE);
    if (s_csv) { s_csvOpen = true; s_csv.print("mac,how,id,rssi\n"); }
  }

  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(99);

  while (!feature_exit_requested && !featureExitButtonPressed()) {
    draw(true, "(wifi..)");
    scanWiFi();
    if (feature_exit_requested || featureExitButtonPressed()) break;
    draw(true, "(ble..)");
    scanBLE(scan);
    draw(false, "");
    Serial.printf("[flock] %d hits, heap=%u\n", s_count, ESP.getFreeHeap());
    for (int k = 0; k < 40 && !feature_exit_requested && !featureExitButtonPressed(); k++) delay(30);
  }

  scan->stop();
  scan->clearResults();
  WiFi.scanDelete();
  if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
  setTouchButtonInputEnabled(false);
  Serial.printf("[flock] stopped: %d hits\n", s_count);
}

}  // namespace FlockDetector
