// ===================================================================
// bySaw RayBan Meta detector — find nearby Ray-Ban Meta smart glasses (anti-
// surveillance / hidden-camera recon). Matches the Meta BLE service UUID 0xFD5F,
// the Meta company id 0x01EC in manufacturer data, and "ray-ban"/"meta" names.
// Shows name, MAC and an RSSI proximity bar; logs to /rayban/rayban-*.csv.
// SELECT exits. Detection signatures ported from nyanBOX (jbohack, MIT licence).
// ===================================================================
#include "config.h"
#include "shared.h"
#include "RaybanDetector.h"
#include <SD.h>
#include <string>

extern TFT_eSPI tft;
extern bool feature_active;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace RaybanDetector {

struct Dev { char mac[18]; char name[24]; int rssi; };
static const int MAXD = 40;
static Dev s_list[MAXD];
static int s_count = 0;

static File s_csv;
static bool s_csvOpen = false;

// Returns true if a BLE advert looks like Ray-Ban Meta glasses.
static bool isRayBan(BLEAdvertisedDevice &d) {
  if (d.haveServiceUUID()) {
    std::string u = d.getServiceUUID().toString();
    for (auto &ch : u) ch = tolower(ch);
    if (u.find("fd5f") != std::string::npos) return true;  // Meta 16-bit svc UUID
  }
  std::string mfr = d.getManufacturerData();
  if (mfr.size() >= 2) {  // company id is little-endian: 0x01EC -> EC 01
    const uint8_t c0 = (uint8_t)mfr[0], c1 = (uint8_t)mfr[1];
    if (c0 == 0xEC && c1 == 0x01) return true;  // Meta Platforms
  }
  std::string nm = d.getName();
  for (auto &ch : nm) ch = tolower(ch);
  if (nm.find("ray-ban") != std::string::npos || nm.find("rayban") != std::string::npos ||
      nm.find("meta view") != std::string::npos)
    return true;
  return false;
}

static void add(const char *mac, const char *name, int rssi) {
  for (int i = 0; i < s_count; i++) {
    if (strcmp(s_list[i].mac, mac) == 0) { s_list[i].rssi = rssi; return; }
  }
  if (s_count < MAXD) {
    Dev &t = s_list[s_count++];
    strncpy(t.mac, mac, sizeof(t.mac) - 1); t.mac[sizeof(t.mac) - 1] = 0;
    strncpy(t.name, name, sizeof(t.name) - 1); t.name[sizeof(t.name) - 1] = 0;
    t.rssi = rssi;
    if (s_csvOpen) { s_csv.printf("%s,%s,%d\n", mac, name, rssi); s_csv.flush(); }
  }
}

static void draw(bool scanning) {
  tft.fillRect(0, 0, tft.width(), tft.height(), UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("RayBan Detect", tft.width() / 2, 4, 1);
  tft.setTextSize(1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  char hd[40];
  snprintf(hd, sizeof(hd), "%d glasses %s", s_count, scanning ? "(scanning..)" : "");
  tft.drawCentreString(hd, tft.width() / 2, 24, 1);

  const int rowH = 24, top = 38;
  const int rows = (tft.height() - top - 16) / rowH;
  int start = s_count > rows ? s_count - rows : 0;
  int y = top;
  for (int i = start; i < s_count; i++) {
    const Dev &t = s_list[i];
    tft.setTextColor(UI_WARN, UI_BG);  // glasses = privacy concern -> warn colour
    tft.setCursor(6, y);
    tft.print(t.name[0] ? t.name : "RayBan Meta");
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
    tft.drawCentreString("no glasses nearby", tft.width() / 2, top + 20, 1);
  }
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

void run() {
  feature_active = true;
  setTouchButtonInputEnabled(true);  // enable touch SELECT slot for touch-only exit
  feature_exit_requested = false;
  pauseBackgroundRadioTasks();
  s_count = 0;
  tft.fillScreen(UI_BG);

  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/rayban");
    char path[40];
    snprintf(path, sizeof(path), "/rayban/rayban-%lu.csv", (unsigned long)(millis() / 1000));
    s_csv = SD.open(path, FILE_WRITE);
    if (s_csv) { s_csvOpen = true; s_csv.print("mac,name,rssi\n"); }
  }

  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(99);

  while (!feature_exit_requested && !featureExitButtonPressed()) {
    draw(true);
    BLEScanResults res = scan->start(1, false);  // 1s scan so SELECT/exit polls often
    for (int i = 0; i < res.getCount(); i++) {
      BLEAdvertisedDevice d = res.getDevice(i);
      if (!isRayBan(d)) continue;
      std::string mac = d.getAddress().toString();
      std::string nm = d.getName();
      add(mac.c_str(), nm.empty() ? "RayBan Meta" : nm.c_str(), d.getRSSI());
    }
    scan->clearResults();
    draw(false);
    Serial.printf("[rayban] %d found, heap=%u\n", s_count, ESP.getFreeHeap());
    for (int k = 0; k < 40 && !feature_exit_requested && !featureExitButtonPressed(); k++) delay(30);
  }

  scan->stop();
  scan->clearResults();
  if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
  setTouchButtonInputEnabled(false);
  Serial.printf("[rayban] stopped: %d glasses\n", s_count);
}

}  // namespace RaybanDetector
