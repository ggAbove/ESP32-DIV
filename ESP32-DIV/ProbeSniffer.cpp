// ===================================================================
// bySaw Probe Request Sniffer  (recon — "what networks are phones looking for")
//
// Channel-hops 2.4GHz in promiscuous MODE_NULL, captures 802.11 probe-request
// frames, and extracts each device's MAC + the SSID it is actively searching for
// (the saved networks a phone broadcasts when looking to reconnect). Shows a live
// list and logs to /probes/probes.csv. Great for picking evil-twin targets.
// (Feature inspired by Bruce / Evil-Cardputer WiFi recon.) SELECT exits.
//
// Reuses the proven Pwnagotchi sniffer pattern: never touch SD in the Wi-Fi
// callback — copy hits into a queue and process them on the main task.
// ===================================================================
#include "config.h"
#include "shared.h"
#include "ProbeSniffer.h"
#include <SD.h>
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

extern TFT_eSPI tft;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace ProbeSniffer {

struct Hit { uint8_t mac[6]; uint8_t ssidLen; char ssid[33]; };

static QueueHandle_t s_q = nullptr;
static volatile bool s_paused = false;
static volatile uint32_t s_total = 0;  // probe frames seen
static volatile uint32_t s_all = 0;    // DEBUG: all frames received
static uint8_t  s_channel = 1;

// unique (mac, ssid) list
static const int  MAXE = 64;
static Hit  s_list[MAXE];
static int  s_count = 0;
static int  s_scroll = 0;

static File s_csv;
static bool s_csvOpen = false;

static void IRAM_ATTR cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (s_paused) return;
  const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *fr = p->payload;
  s_all++;
  const int len = p->rx_ctrl.sig_len;
  if (len < 26) return;
  // probe request = mgmt (type 0) subtype 4
  if (((fr[0] >> 2) & 0x3) != 0 || ((fr[0] >> 4) & 0xF) != 4) return;
  s_total++;
  // SSID IE is the first tagged param after the 24-byte header: id 0, len, bytes
  if (fr[24] != 0x00) return;
  uint8_t sl = fr[25];
  if (sl > 32) return;
  if (len < 26 + sl) return;

  Hit h;
  memcpy(h.mac, fr + 10, 6);  // addr2 = source (the probing device)
  h.ssidLen = sl;
  memcpy(h.ssid, fr + 26, sl);
  h.ssid[sl] = 0;
  if (s_q) xQueueSend(s_q, &h, 0);
}

static bool sameHit(const Hit &a, const Hit &b) {
  return a.ssidLen == b.ssidLen && memcmp(a.mac, b.mac, 6) == 0 &&
         memcmp(a.ssid, b.ssid, a.ssidLen) == 0;
}

static void addHit(const Hit &h) {
  if (h.ssidLen == 0) return;  // broadcast probe (no named SSID) — skip the list
  for (int i = 0; i < s_count; i++)
    if (sameHit(s_list[i], h)) return;  // already have it
  if (s_count < MAXE) {
    s_list[s_count++] = h;
    if (s_csvOpen) {
      char line[80];
      snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X,%s\n", h.mac[0], h.mac[1],
               h.mac[2], h.mac[3], h.mac[4], h.mac[5], h.ssid);
      s_csv.print(line);
      s_csv.flush();
    }
  }
}

static void draw() {
  tft.fillRect(0, 22, tft.width(), tft.height() - 22, UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("Probe Sniffer", tft.width() / 2, 4, 1);

  tft.setTextSize(1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  char hd[40];
  snprintf(hd, sizeof(hd), "CH %-2d  found %d  seen %lu", s_channel, s_count,
           (unsigned long)s_total);
  tft.drawCentreString(hd, tft.width() / 2, 24, 1);

  // list of MAC -> SSID (most recent at bottom; auto-scroll to tail)
  const int rowH = 22, top = 40;
  const int rows = (tft.height() - top - 16) / rowH;
  int start = s_count > rows ? s_count - rows : 0;
  int y = top;
  for (int i = start; i < s_count; i++) {
    const Hit &h = s_list[i];
    char mac[20];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X", h.mac[0], h.mac[1], h.mac[2],
             h.mac[3], h.mac[4], h.mac[5]);
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.setCursor(6, y);
    tft.print(mac);
    tft.setTextColor(UI_OK, UI_BG);
    tft.setCursor(6, y + 9);
    tft.print(h.ssid);
    tft.drawFastHLine(0, y + rowH - 2, tft.width(), UI_LINE);
    y += rowH;
  }

  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

void run() {
  pauseBackgroundRadioTasks();
  s_total = 0;
  s_all = 0;
  s_count = 0;
  s_scroll = 0;
  s_channel = 1;
  s_paused = false;
  s_q = xQueueCreate(24, sizeof(Hit));

  tft.fillScreen(UI_BG);

  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/probes");
    char path[40];
    snprintf(path, sizeof(path), "/probes/probes-%lu.csv", (unsigned long)(millis() / 1000));
    s_csv = SD.open(path, FILE_WRITE);
    if (s_csv) {
      s_csvOpen = true;
      s_csv.print("mac,ssid\n");
      Serial.printf("[probe] logging %s\n", path);
    }
  }

  wifi_mode_t wm;
  esp_err_t e_mode = esp_wifi_get_mode(&wm);
  if (e_mode == ESP_ERR_WIFI_NOT_INIT) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_start();
  }
  esp_err_t e_sm = esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&cb);
  esp_err_t e_pr = esp_wifi_set_promiscuous(true);
  esp_err_t e_ch = esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[probe] wifi: getmode=0x%x(m%d) setmode=0x%x promisc=0x%x ch=0x%x\n", e_mode, wm,
                e_sm, e_pr, e_ch);

  uint32_t lastHop = 0, lastDraw = 0, lastLog = 0;
  int lastCount = -1;
  while (!feature_exit_requested && !featureExitButtonPressed()) {
    uint32_t now = millis();

    Hit h;
    while (s_q && xQueueReceive(s_q, &h, 0) == pdTRUE) addHit(h);

    if (now - lastHop > 1000) {
      s_channel = (s_channel % 13) + 1;
      esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
      lastHop = now;
    }
    if (now - lastDraw > 400 || s_count != lastCount) {
      draw();
      lastCount = s_count;
      lastDraw = now;
    }
    if (now - lastLog > 3000) {
      Serial.printf("[probe] ch=%d found=%d probes=%lu allframes=%lu heap=%u\n", s_channel,
                    s_count, (unsigned long)s_total, (unsigned long)s_all, ESP.getFreeHeap());
      lastLog = now;
    }
    delay(10);
  }

  s_paused = true;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  esp_wifi_set_mode(WIFI_MODE_STA);
  if (s_q) { vQueueDelete(s_q); s_q = nullptr; }
  if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
  Serial.printf("[probe] stopped: %d unique networks\n", s_count);
}

}  // namespace ProbeSniffer
