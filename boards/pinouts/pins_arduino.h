#ifndef Pins_Arduino_h
#define Pins_Arduino_h

#include "soc/soc_caps.h"
#include <stdint.h>

#ifndef DEVICE_NAME
#define DEVICE_NAME "ESP32-DIV-v2"
#endif

// =============================================
// USB (ESP32-S3 native USB-CDC)
// =============================================
#define USB_VID 0x303a
#define USB_PID 0x1001

// =============================================
// UART0 (console) - ESP32-S3 defaults
// =============================================
static const uint8_t TX = 43;
static const uint8_t RX = 44;

// =============================================
// I2C bus - PCF8574 button expander @0x20 + expansion
// NOTE: SDA/SCL pins are placeholders (S3 defaults). The DIV v2 schematic
// pins for the PCF8574 are not yet confirmed; buttons are unused for now
// (touch-driven UI). Update once verified to enable PCF8574 navigation.
// =============================================
#define GROVE_SDA 8
#define GROVE_SCL 9
static const uint8_t SDA = GROVE_SDA;
static const uint8_t SCL = GROVE_SCL;

// =============================================
// Module SPI bus (FSPI) - shared by SD + CC1101 + NRF24
// (separate from the TFT/touch HSPI bus on 35/36/37)
// =============================================
#define SPI_SCK_PIN  12
#define SPI_MOSI_PIN 11
#define SPI_MISO_PIN 13
#define SPI_SS_PIN   5

static const uint8_t SS   = SPI_SS_PIN;
static const uint8_t MOSI = SPI_MOSI_PIN;
static const uint8_t SCK  = SPI_SCK_PIN;
static const uint8_t MISO = SPI_MISO_PIN;

// =============================================
// Deep-sleep wake on BOOT button (GPIO0)
// =============================================
#define DEEPSLEEP_WAKEUP_PIN 0
#define DEEPSLEEP_PIN_ACT LOW

#endif /* Pins_Arduino_h */
