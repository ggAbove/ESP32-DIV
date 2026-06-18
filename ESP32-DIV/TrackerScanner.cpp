// ===================================================================
// bySaw BLE Tracker Scanner — find nearby Apple Find My / AirTag, Tile, Samsung
// SmartTag and other BLE trackers (anti-stalking + recon). Shows type, MAC, name
// and an RSSI proximity bar; logs to /trackers/trackers-*.csv. SELECT exits.
// (Feature inspired by Bruce / Evil-Cardputer BLE recon.)
// ===================================================================
#include "config.h"
#include "shared.h"
#include "TrackerScanner.h"
#include <SD.h>
#include <string>

extern TFT_eSPI tft;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace TrackerScanner {

struct Trk { char mac[18]; char name[20]; char type[14]; int rssi; };
static const int MAXT = 40;
static Trk s_list[MAXT];
static int s_count = 0;

static File s_csv;
static bool s_csvOpen = false;

static const char *classify(BLEAdvertisedDevice &d) {
  std::string mfr = d.getManufacturerData();
  if (mfr.size() >= 3) {
    const uint8_t c0 = (uint8_t)mfr[0], c1 = (uint8_t)mfr[1], c2 = (uint8_t)mfr[2];
    if (c0 == 0x4C && c1 == 0x00 && c2 == 0x12) return "AirTag/FindMy";  // Apple Find My
    if (c0 == 0x75 && c1 == 0x00) return "Samsung Tag";                  // Samsung mfr
  }
  if (d.haveServiceUUID()) {
    std::string u = d.getServiceUUID().toString();
    for (auto &ch : u) ch = tolower(ch);
    if (u.find("feed") != std::string::npos || u.find("feec") != std::string::npos) return "Tile";
    if (u.find("fd5a") != std::string::npos) return "SmartThings";
    if (u.find("fd44") != std::string::npos) return "Apple FindMy";
  }
  return nullptr;  // not a recognised tracker
}

static void addTracker(const char *mac, const char *name, const char *type, int rssi) {
  for (int i = 0; i < s_count; i++) {
    if (strcmp(s_list[i].mac, mac) == 0) {  // update rssi/name
      s_list[i].rssi = rssi;
      return;
    }
  }
  if (s_count < MAXT) {
    Trk &t = s_list[s_count++];
    strncpy(t.mac, mac, sizeof(t.mac) - 1); t.mac[sizeof(t.mac) - 1] = 0;
    strncpy(t.name, name, sizeof(t.name) - 1); t.name[sizeof(t.name) - 1] = 0;
    strncpy(t.type, type, sizeof(t.type) - 1); t.type[sizeof(t.type) - 1] = 0;
    t.rssi = rssi;
    if (s_csvOpen) { s_csv.printf("%s,%s,%s,%d\n", mac, type, name, rssi); s_csv.flush(); }
  }
}

static void draw(bool scanning) {
  tft.fillRect(0, 0, tft.width(), tft.height(), UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("Tracker Scan", tft.width() / 2, 4, 1);
  tft.setTextSize(1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  char hd[40];
  snprintf(hd, sizeof(hd), "%d trackers %s", s_count, scanning ? "(scanning..)" : "");
  tft.drawCentreString(hd, tft.width() / 2, 24, 1);

  const int rowH = 24, top = 38;
  const int rows = (tft.height() - top - 16) / rowH;
  int start = s_count > rows ? s_count - rows : 0;
  int y = top;
  for (int i = start; i < s_count; i++) {
    const Trk &t = s_list[i];
    uint16_t col = (strstr(t.type, "FindMy") || strstr(t.type, "AirTag")) ? UI_WARN : UI_OK;
    tft.setTextColor(col, UI_BG);
    tft.setCursor(6, y);
    tft.print(t.type);
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.setCursor(6, y + 10);
    tft.print(t.mac);
    // rssi proximity bar (right side): -40 near .. -100 far
    int pct = t.rssi + 100; if (pct < 0) pct = 0; if (pct > 60) pct = 60;
    int w = (pct * 70) / 60;
    tft.drawRect(tft.width() - 76, y + 4, 72, 8, UI_LINE);
    tft.fillRect(tft.width() - 75, y + 5, w, 6, col);
    tft.drawFastHLine(0, y + rowH - 2, tft.width(), UI_LINE);
    y += rowH;
  }
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

void run() {
  pauseBackgroundRadioTasks();
  s_count = 0;
  tft.fillScreen(UI_BG);

  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/trackers");
    char path[40];
    snprintf(path, sizeof(path), "/trackers/trackers-%lu.csv", (unsigned long)(millis() / 1000));
    s_csv = SD.open(path, FILE_WRITE);
    if (s_csv) { s_csvOpen = true; s_csv.print("mac,type,name,rssi\n"); }
  }

  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(99);

  while (!feature_exit_requested && !featureExitButtonPressed()) {
    draw(true);
    BLEScanResults res = scan->start(3, false);
    for (int i = 0; i < res.getCount(); i++) {
      BLEAdvertisedDevice d = res.getDevice(i);
      const char *type = classify(d);
      if (!type) continue;
      std::string mac = d.getAddress().toString();
      std::string nm = d.getName();
      addTracker(mac.c_str(), nm.empty() ? "-" : nm.c_str(), type, d.getRSSI());
    }
    scan->clearResults();
    draw(false);
    Serial.printf("[tracker] %d found, heap=%u\n", s_count, ESP.getFreeHeap());
    // brief responsive wait for exit
    for (int k = 0; k < 30 && !feature_exit_requested && !featureExitButtonPressed(); k++) delay(10);
  }

  scan->stop();
  scan->clearResults();
  if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
  Serial.printf("[tracker] stopped: %d trackers\n", s_count);
}

}  // namespace TrackerScanner
