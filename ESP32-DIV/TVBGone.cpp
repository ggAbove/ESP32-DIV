// ===================================================================
// bySaw TV-B-Gone — blasts a curated set of TV power(-off) IR codes across the
// major brands/protocols. Point the IR LED at a TV and most will switch off.
// (Classic Mitch Altman / EvilCrow / Flipper feature.) SELECT exits/stops.
// ===================================================================
#include "config.h"
#include "shared.h"
#include "TVBGone.h"
#include <IRsend.h>

extern TFT_eSPI tft;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace TVBGone {

enum { P_NEC, P_SONY12, P_SONY15, P_SONY20, P_SAMSUNG, P_PANASONIC, P_RC5, P_RC6, P_JVC, P_LG };

struct Code { uint8_t proto; uint64_t data; uint16_t bits; uint32_t addr; const char *brand; };

// A compact, well-known TV power-code set (covers the bulk of TVs in the wild).
static const Code kCodes[] = {
    {P_SAMSUNG, 0xE0E040BF, 32, 0, "Samsung"},
    {P_NEC, 0x20DF10EF, 32, 0, "LG"},
    {P_LG, 0x20DF10EF, 28, 0, "LG2"},
    {P_NEC, 0x02FD48B7, 32, 0, "Toshiba"},
    {P_NEC, 0x57E3E817, 32, 0, "Hisense"},
    {P_NEC, 0x4FB0CF3, 32, 0, "TCL"},
    {P_NEC, 0x40BF, 16, 0, "Sharp"},
    {P_NEC, 0xC1AA09F6, 32, 0, "Philips"},
    {P_SONY12, 0xA90, 12, 0, "Sony12"},
    {P_SONY15, 0xA90, 15, 0, "Sony15"},
    {P_SONY20, 0xA90, 20, 0, "Sony20"},
    {P_PANASONIC, 0x100BCBD, 48, 0x4004, "Panasonic"},
    {P_RC5, 0x100C, 13, 0, "Philips/RC5"},
    {P_RC6, 0xC, 20, 0, "Philips/RC6"},
    {P_JVC, 0xC5E8, 16, 0, "JVC"},
    {P_NEC, 0x10EF00FF, 32, 0, "Vizio"},
    {P_NEC, 0x8166817E, 32, 0, "RCA"},
    {P_NEC, 0xFD00FF, 32, 0, "Insignia"},
};
static const int N = sizeof(kCodes) / sizeof(kCodes[0]);

static IRsend s_ir(IR_TX_PIN);

static void sendOne(const Code &c) {
  switch (c.proto) {
    case P_NEC:       s_ir.sendNEC(c.data, c.bits); break;
    case P_LG:        s_ir.sendLG(c.data, c.bits); break;
    case P_SONY12:
    case P_SONY15:
    case P_SONY20:    s_ir.sendSony(c.data, c.bits, 2); break;
    case P_SAMSUNG:   s_ir.sendSAMSUNG(c.data, c.bits); break;
    case P_PANASONIC: s_ir.sendPanasonic(c.addr, c.data, c.bits); break;
    case P_RC5:       s_ir.sendRC5(c.data, c.bits); break;
    case P_RC6:       s_ir.sendRC6(c.data, c.bits); break;
    case P_JVC:       s_ir.sendJVC(c.data, c.bits, 0); break;
    default: break;
  }
}

void run() {
  s_ir.begin();
  tft.fillScreen(UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(3);
  tft.drawCentreString("TV-B-Gone", tft.width() / 2, 30, 1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.setTextSize(1);
  tft.drawCentreString("point IR at the TV", tft.width() / 2, 70, 1);

  int round = 0;
  while (!feature_exit_requested && !featureExitButtonPressed()) {
    round++;
    for (int i = 0; i < N && !feature_exit_requested && !featureExitButtonPressed(); i++) {
      // progress bar + current brand
      tft.fillRect(0, 110, tft.width(), 90, UI_BG);
      tft.setTextSize(2);
      tft.setTextColor(UI_OK, UI_BG);
      char l[24];
      snprintf(l, sizeof(l), "%s", kCodes[i].brand);
      tft.drawCentreString(l, tft.width() / 2, 120, 1);
      tft.setTextSize(1);
      tft.setTextColor(UI_TEXT, UI_BG);
      snprintf(l, sizeof(l), "%d / %d   round %d", i + 1, N, round);
      tft.drawCentreString(l, tft.width() / 2, 150, 1);
      int w = ((i + 1) * (tft.width() - 40)) / N;
      tft.drawRect(20, 170, tft.width() - 40, 10, UI_LINE);
      tft.fillRect(21, 171, w - 2, 8, UI_ICON);

      sendOne(kCodes[i]);
      Serial.printf("[tvbgone] sent %s (%d/%d)\n", kCodes[i].brand, i + 1, N);
      for (int k = 0; k < 12 && !featureExitButtonPressed(); k++) delay(10);  // ~120ms gap
    }
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.drawCentreString("sweep done - SEL exit", tft.width() / 2, tft.height() - 14, 1);
    for (int k = 0; k < 60 && !feature_exit_requested && !featureExitButtonPressed(); k++) delay(10);
  }
  Serial.println("[tvbgone] stopped");
}

}  // namespace TVBGone
