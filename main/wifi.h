#pragma once

// ====================================================================
// INCLUDES 
// ====================================================================

#include "common.h"
#include "esp_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

// ====================================================================
// DEFINES 
// ====================================================================

#define WIFI_DEFAULT_MAX_ATTEMPTS 5
#define WIFI_DEFAULT_RECONNECT_TIMER (5*60) //seconds

#define MAX_CHARS_SSID           32
#define MAX_CHARS_PASSWORD       64
#define MAX_NUM_ACCESSPOINTS     14
#define INFINITE_CONN_ATTEMPTS   0

// ====================================================================
// TYPEDEFS 
// ====================================================================

///
/// @brief The context for WiFi connection information (SSID, password, and authentication mode)
///
typedef enum
{
    WIFI_CONTEXT_PRIMARY,  /**< Primary context */
    WIFI_CONTEXT_TEST,     /**< Test context */
    WIFI_CONTEXT_MAX
} WifiContext;

///
/// @brief Connection status
///
typedef enum
{
    WIFI_STATUS_NONE,                   /**< No status */
    WIFI_STATUS_DISABLED,               /**< WiFi is disabled */
    WIFI_STATUS_CONNECTING,             /**< Attempting to connect to access point */
    WIFI_STATUS_NOT_CONNECTED,          /**< Not connected, or failed to connect to access point */
    WIFI_STATUS_CONNECTED,              /**< Connected to access point and the internet */
    WIFI_STATUS_CONNECTED_NO_INTERNET   /**< Connected to access point but not the internet */
} WifiStatus;

///
/// @brief WiFi signal strength
///
typedef enum
{
    WIFI_SIGNAL_STRENGTH_UNKNOWN,  /**< Unknown signal strength */
    WIFI_SIGNAL_STRENGTH_HORRIBLE,  /**< Unusable signal strength */
    WIFI_SIGNAL_STRENGTH_WEAK,  /**< Not Good signal strength */
    WIFI_SIGNAL_STRENGTH_OKAY,      /**< Okay signal strength */
    WIFI_SIGNAL_STRENGTH_GREAT, /**< Very Good signal strength */
    WIFI_SIGNAL_STRENGTH_AMAZING,   /**< Amazing signal strength */
} WifiSignalStrength;

///
/// @brief WiFi error codes for `wifi_test_wifi()`
///
typedef enum
{
    WIFI_ERR_NOTHING  = 0,
    WIFI_ERR_SUCCESS  = 1,   /**< success */
    WIFI_ERR_SSID_LEN = 2,   /**< 0 lenght ssid */
    WIFI_ERR_PSWD_LEN = 3,   /**< 0 length pswd */
    WIFI_ERR_CONFIG   = 4,   /**< failed to configure wifi */
    WIFI_ERR_START    = 5,   /**< failed to start wifi */
    WIFI_ERR_SSID     = 6,   /**< ssid is likely incorrect */
    WIFI_ERR_PSWD     = 7,   /**< pswd is likely incorrect */
    WIFI_ERR_OTHER    = 255, /**< other */
} WifiErrCode;

///
/// @brief Access point info
///
typedef struct
{
    uint8_t ssid[MAX_CHARS_SSID+1];     /**< SSID */
    uint8_t rssi;                       /**< RSSI [0-255] (127 is the strongest) */
    wifi_auth_mode_t authmode;     /**< Wifi auth_mode type (0 - 6) */
} wifi_accesspoint_t;


typedef wifi_auth_mode_t WifiAuthMode;

// ====================================================================
// GLOBAL VARIABLES
// ====================================================================

extern const char* wifi_signal_strength_str[];
extern const char* wifi_status_str[];

// ====================================================================
// GLOBAL FUNCTIONS
// ====================================================================

bool wifi_init();
bool _wifi_deinit();
bool wifi_reinit();
void wifi_debug_logs(bool enable);
bool wifi_enable();
bool wifi_disable();
bool wifi_connect();
bool wifi_disconnect();

bool wifi_set_ssid(char* ssid, WifiContext context);
bool wifi_set_password(char* pswd, WifiContext context);
bool wifi_set_auth_mode(wifi_auth_mode_t auth_mode, WifiContext context);
bool wifi_set_all(char* ssid, char* pswd, wifi_auth_mode_t auth_mode, WifiContext context);

bool wifi_store_ssid(char* ssid);
bool wifi_load_ssid(char* ssid, int max_len);
bool wifi_store_pass(char* pass);
bool wifi_load_pass(char* pass, int max_len);
bool wifi_store_auth(uint8_t auth);
bool wifi_load_auth(uint8_t* auth);
bool wifi_load_credentials();

void wifi_set_max_reconnect_attempts(uint8_t attempts);
void wifi_set_reconnect_time(int seconds);
bool wifi_test_wifi(int timeout_ms, uint8_t* error_code);
bool wifi_test_wifi_task(bool* exec_result, int timeout_ms, uint8_t* error_code, void (*post_process_func)());
bool wifi_list_ap_task(bool* exec_result, void (*post_process_func)());
bool wifi_test_task_running();
bool wifi_wait_for_connect(int timeout_ms);
bool wifi_wait_for_internet(int timeout_ms);
bool wifi_list_ap();
uint8_t wifi_get_num_accesspoints();
bool wifi_get_ap_info(uint8_t index, wifi_accesspoint_t* ap_info);
WifiStatus wifi_get_status();
bool wifi_get_internet_status();
bool wifi_get_ip_addr(char* ret_str);
bool wifi_get_ssid(char* ret_ssid, WifiContext context);
bool wifi_get_password(char* ret_pswd, WifiContext context);
void wifi_get_auth_mode(wifi_auth_mode_t* ret_auth_mode, WifiContext context);
bool wifi_get_rssi(int8_t* ret_rssi);
bool wifi_get_rssi_unsigned(uint8_t* ret_rssi);
WifiSignalStrength wifi_get_signal_strength(int8_t rssi);
WifiSignalStrength wifi_get_current_signal_strength();
bool wifi_enable_rssi_notifications();
void wifi_disable_rssi_notifications();

#ifdef __cplusplus
}
#endif
 
