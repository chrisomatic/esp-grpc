// ====================================================================
// INCLUDES
// ====================================================================

// Third party
#include "lwip/err.h"
#include "lwip/sys.h"

#include "common.h"
#include "wifi.h"
#include "storage.h"
#include "datetime.h"


#if IDF_VERSION == 3
#include "esp_event_loop.h"
#endif

// ====================================================================
// DEFINES
// ====================================================================

#if IDF_VERSION == 4
    #define EVT_STA_STOP            WIFI_EVENT_STA_STOP
    #define EVT_STA_START           WIFI_EVENT_STA_START
    #define EVT_STA_CONNECTED       WIFI_EVENT_STA_CONNECTED
    #define EVT_STA_DISCONNECTED    WIFI_EVENT_STA_DISCONNECTED
    #define EVT_AP_START            WIFI_EVENT_AP_START
    #define EVT_SCAN_DONE           WIFI_EVENT_AP_STOP
    #define EVT_GOT_IP              IP_EVENT_STA_GOT_IP
    #define EVT_LOST_IP             IP_EVENT_STA_LOST_IP
#else
    #define EVT_STA_STOP            SYSTEM_EVENT_STA_STOP
    #define EVT_STA_START           SYSTEM_EVENT_STA_START
    #define EVT_STA_CONNECTED       SYSTEM_EVENT_STA_CONNECTED
    #define EVT_STA_DISCONNECTED    SYSTEM_EVENT_STA_DISCONNECTED
    #define EVT_AP_START            SYSTEM_EVENT_AP_START
    #define EVT_SCAN_DONE           SYSTEM_EVENT_SCAN_DONE
    #define EVT_GOT_IP              SYSTEM_EVENT_STA_GOT_IP
    #define EVT_LOST_IP             SYSTEM_EVENT_STA_LOST_IP
#endif

// ====================================================================
// MACROS
// ====================================================================

#define DEBUG(format,...) do { if(debug_logs) LOGI(format,##__VA_ARGS__); } while(0);

// ====================================================================
// STATIC VARIABLES
// ====================================================================

// love using bools with wifi
static bool debug_logs = false;
static bool internet_connected = false;     // true if connected to internet
static bool wifi_connected = false;         // is the wifi currently connected
static bool wifi_connecting = false;        // is wifi currently trying to connect
static bool wifi_should_connect = false;    // true if wifi_connect() has been called
static bool wifi_enabled = false;           // is wifi enabled


static char wifi_ssid[WIFI_CONTEXT_MAX][MAX_CHARS_SSID+1] = {0};        // wifi ssid
static char wifi_pswd[WIFI_CONTEXT_MAX][MAX_CHARS_PASSWORD+1] = {0};    // wifi password
static uint8_t wifi_auth_mode[WIFI_CONTEXT_MAX] = {0};                  // wifi auth_mode context

static WifiStatus wifi_status = WIFI_STATUS_NONE;
static uint8_t max_attempts = 0; // number of attempts before waiting and trying to connect again
static uint8_t connect_attempts = 0;
static int wifi_reconnect_time = 0;
static esp_timer_handle_t wifi_reconnect_timer;

static uint8_t err_code = 0;
static uint8_t num_accesspoints = 0; // count of access points

#if IDF_VERSION_MAJOR_MINOR > 40
static esp_ip4_addr_t ip_addr = {0};
static esp_netif_t* netif = NULL;
#else
static ip4_addr_t ip_addr = {0};
#endif


static wifi_accesspoint_t accesspoints[MAX_NUM_ACCESSPOINTS] = {}; // list of access points
static int test_task_timeout_ms = 20;
static uint8_t test_task_action = 0; // 1 = test wifi connection, 2 = list ap
static uint8_t* test_task_error_code = NULL; // for wifi connection test
static bool* test_task_exec_result = NULL;   // says whether or not the action executed successfully
static bool test_task_created = false;
static task_config_t test_task_config = {0};
static void (*test_task_post_process_func)() = NULL;

// ====================================================================
// GLOBAL VARIABLES
// ====================================================================

const char* wifi_status_str[] = {
    "NONE",
    "DISABLED",
    "CONNECTING",
    "NOT CONNECTED",
    "CONNECTED",
    "CONNECTED NO INTERNET",
};


// ====================================================================
// STATIC PROTOTYPES
// ====================================================================

static bool _wifi_connect();
static bool config_connection(WifiContext context);
static esp_err_t wait_for_start(int ms);
static esp_err_t wait_for_stop(int ms);

#if IDF_VERSION == 4
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
#else
static esp_err_t wifi_event_handler(void *ctx, system_event_t *event);
#endif

static void IRAM_ATTR wifi_reconnect_routine(void* arg);
static uint8_t convert_wifi_disconnect_reason(uint8_t reason);
static bool is_ssid_unique_in_list(uint8_t* ssid);
static void update_wifi_status();

static void wifi_test_task(void* arg);
static bool create_wifi_test_task(int* ret);

// ====================================================================
// GLOBAL FUNCTIONS
// ====================================================================

// initialization
// ----------------------------------------------------------------------------------------------------------------


bool wifi_init()
{
    // initialize some variables
    err_code = WIFI_ERR_OTHER;
    if(max_attempts == 0) max_attempts = WIFI_DEFAULT_MAX_ATTEMPTS;
    if(wifi_reconnect_time == 0) wifi_reconnect_time = WIFI_DEFAULT_RECONNECT_TIMER;

    // disable idf wifi logs
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    esp_log_level_set("wifi_init", ESP_LOG_ERROR);
    esp_log_level_set("phy_init", ESP_LOG_ERROR);
    esp_log_level_set("esp_netif_handlers", ESP_LOG_ERROR);

    esp_err_t err;

    // Init NVS
    store_nvs_init();

#if IDF_VERSION_MAJOR_MINOR > 40

    // Init underlying stack
    esp_netif_init();

    // Create default event loop
    esp_event_loop_create_default();

    // Create default station
    netif = esp_netif_create_default_wifi_sta();

#elif IDF_VERSION_MAJOR_MINOR == 40

    tcpip_adapter_init();

    esp_event_loop_create_default();

#else

    tcpip_adapter_init();
    err = esp_event_loop_init(wifi_event_handler, NULL);
    if(err) {
        LOGE("Failed to initialize event loop, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

#endif


    // Pass wifi stack config parameters to stack init
    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    wifi_init_config.nvs_enable = 0;

    err = esp_wifi_init(&wifi_init_config);
    if(err) {
        LOGE("Failed to initialize wifi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

#if IDF_VERSION == 4
    // Produce handles and register event handler for WIFI and IP event occurrences 
    // esp_event_handler_instance_t handle_anyid;
    // esp_event_handler_instance_t handle_gotip;

    err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
    if(err) {
        LOGE("Failed to register wifi event handler, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    err = esp_event_handler_register(IP_EVENT,  ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
    if(err) {
        LOGE("Failed to register ip event handler, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }
#endif


    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if(err != ESP_OK) {
        err_code = WIFI_ERR_CONFIG;
        LOGE("Failed to set wifi mode, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    // esp_event_handler_instance_register(WIFI_EVENT,ESP_EVENT_ANY_ID,&wifi_event_handler,NULL,&handle_anyid);
    // esp_event_handler_instance_register(IP_EVENT,IP_EVENT_STA_GOT_IP,&wifi_event_handler,NULL,&handle_gotip);

    esp_timer_create_args_t wifi_reconnect_timer_args = {};
    wifi_reconnect_timer_args.callback = &wifi_reconnect_routine;
    wifi_reconnect_timer_args.name = "wifi_reconnect_routine";

    err = esp_timer_create((const esp_timer_create_args_t*)&wifi_reconnect_timer_args, &wifi_reconnect_timer);
    if(err) {
        LOGE("Failed to create reconnection timer, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    update_wifi_status();
    test_task_timeout_ms = 20;
    test_task_config.core = 1;
    test_task_config.priority = 1;
    test_task_config.stack_size = 3000;
    LOGI("Finished initialization of wifi station");
    return true;
}

bool _wifi_deinit()
{
    esp_err_t err;
    wifi_disable();

#if IDF_VERSION == 4
    err = esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler);
    if(err) {
        LOGE("Failed to unregister wifi event handler, error: 0x%x (%s)", err, esp_err_to_name(err));
        // return false;
    }

    err = esp_event_handler_unregister(IP_EVENT,  ESP_EVENT_ANY_ID, &wifi_event_handler);
    if(err) {
        LOGE("Failed to unregister ip event handler, error: 0x%x (%s)", err, esp_err_to_name(err));
        // return false;
    }
#endif

    esp_timer_stop(wifi_reconnect_timer);
    internet_connected = false;

    err = esp_wifi_deinit();
    if(err) {
        LOGE("Failed to deinitialize wifi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

#if IDF_VERSION_MAJOR_MINOR > 40
    err = esp_wifi_clear_default_wifi_driver_and_handlers(netif);
    if(err) {
        LOGE("Failed to clear wifi driver, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    esp_netif_destroy(netif);
#endif

    return true;
}

bool wifi_reinit()
{
    esp_err_t err;

#if IDF_VERSION_MAJOR_MINOR > 40
    netif = esp_netif_create_default_wifi_sta();
#endif


    // Pass wifi stack config parameters to stack init
    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    wifi_init_config.nvs_enable = 0;

    err = esp_wifi_init(&wifi_init_config);
    if(err) {
        LOGE("Failed to initialize wifi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

#if IDF_VERSION == 4
    err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
    if(err) {
        LOGE("Failed to register wifi event handler, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    err = esp_event_handler_register(IP_EVENT,  ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
    if(err) {
        LOGE("Failed to register ip event handler, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }
#endif

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if(err != ESP_OK) {
        err_code = WIFI_ERR_CONFIG;
        LOGE("Failed to set wifi mode, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    return true;
}


void wifi_debug_logs(bool enable)
{
    debug_logs = enable;
}

bool wifi_enable()
{
    if(wifi_enabled) return true;
    bool ret = (wait_for_start(200) == ESP_OK);
    return ret;
}

bool wifi_disable()
{
    if(!wifi_enabled) return true;
    wifi_disconnect();
    bool ret = (wait_for_stop(200) == ESP_OK);
    update_wifi_status();
    return ret;
}

bool wifi_connect()
{
    if(!wifi_enabled) {
        LOGW("Enable wifi before performing this action");
        return false;
    }

    wifi_should_connect = true;

    // already connected
    if(wifi_connected) return true;

    if(!config_connection(WIFI_CONTEXT_PRIMARY)) return false;

    return _wifi_connect();
}


bool wifi_disconnect()
{
    esp_err_t err = esp_timer_stop(wifi_reconnect_timer);
    if(err == ESP_OK) LOGI("Reconnection timer stopped");

    if(!wifi_should_connect) return true;
    if(!wifi_enabled) return true;

    wifi_connecting = false;
    wifi_should_connect = false;

    DEBUG("Disconnecting wifi");
    err = esp_wifi_disconnect();
    delay(200);
    return (err == ESP_OK);
}


bool wifi_set_ssid(char* ssid, WifiContext context)
{
    if(context >= WIFI_CONTEXT_MAX) return false;

    if(strlen(ssid) > MAX_CHARS_SSID || strlen(ssid) == 0) {
        LOGW("Wi-Fi SSID length is not valid");
        return false;
    }

    memset(wifi_ssid[context], 0, MAX_CHARS_SSID);
    memcpy(wifi_ssid[context], ssid, strlen(ssid));
    return true;
}

bool wifi_set_password(char* pswd, WifiContext context)
{
    if(context == WIFI_CONTEXT_MAX) return false;

    if(strlen(pswd) > MAX_CHARS_PASSWORD || strlen(pswd) == 0) {
        LOGW("Wi-Fi password length is not valid");
        return false;
    }

    memset(wifi_pswd[context], 0, MAX_CHARS_PASSWORD);
    memcpy(wifi_pswd[context], pswd, strlen(pswd));
    return true;
}

bool wifi_set_auth_mode(wifi_auth_mode_t auth_mode, WifiContext context)
{
    if(context >= WIFI_CONTEXT_MAX) return false;

    if(auth_mode >= WIFI_AUTH_MAX || auth_mode < 0) {
        LOGW("Wi-Fi auth mode is not valid");
        return false;
    }

    wifi_auth_mode[context] = (uint8_t)auth_mode;
    return true;
}

bool wifi_set_all(char* ssid, char* pswd, wifi_auth_mode_t auth_mode, WifiContext context)
{
    if(context >= WIFI_CONTEXT_MAX) return false;
    if(!wifi_set_ssid(ssid, context)) return false;
    if(!wifi_set_auth_mode(auth_mode, context)) return false;
    if(auth_mode != WIFI_AUTH_OPEN) {
        if(!wifi_set_password(pswd, context)) return false;
    }
    return true;
}

bool wifi_store_ssid(char* ssid)
{
    if(STR_EMPTY(ssid) || strlen(ssid) > MAX_CHARS_SSID)
        return false;
    bool ret = store_nvs_write_str(NVS_NAMESPACE, NVS_KEY_SSID, ssid);
    return ret;
}

bool wifi_load_ssid(char* ssid, int max_len)
{
    bool ret;
    size_t size = 0;
    ret = store_nvs_read_str(NVS_NAMESPACE, NVS_KEY_SSID, NULL, &size);

    if(!ret || size == 0 || size > max_len)
        return false;

    ret = store_nvs_read_str(NVS_NAMESPACE, NVS_KEY_SSID, ssid, &size);
    return ret;
}

bool wifi_store_pass(char* pass)
{
    if(STR_EMPTY(pass) || strlen(pass) > MAX_CHARS_PASSWORD)
        return false;
    bool ret = store_nvs_write_str(NVS_NAMESPACE, NVS_KEY_SSID, pass);
    return ret;
}

bool wifi_load_pass(char* pass, int max_len)
{
    bool ret;
    size_t size = 0;
    ret = store_nvs_read_str(NVS_NAMESPACE, NVS_KEY_PASS, NULL, &size);

    if(!ret || size == 0 || size > max_len)
        return false;

    ret = store_nvs_read_str(NVS_NAMESPACE, NVS_KEY_PASS, pass, &size);
    return ret;
}

bool wifi_store_auth(uint8_t auth)
{
    if(auth >= WIFI_AUTH_MAX)
        return false;
    bool ret = store_nvs_write_u8(NVS_NAMESPACE, NVS_KEY_PASS, auth);
    return ret;
}

bool wifi_load_auth(uint8_t* auth)
{
    return store_nvs_read_u8(NVS_NAMESPACE, NVS_KEY_AUTH, auth);
}

bool wifi_load_credentials()
{
    char ssid[MAX_CHARS_SSID+1] = {};
    char password[MAX_CHARS_PASSWORD+1] = {};
    uint8_t auth_mode = 0;
    bool load_error = false;

    if(!wifi_load_auth(&auth_mode)){
        LOGW("Failed to read auth mode from storage!");
        load_error = true;
    }

    if(!wifi_load_ssid(ssid, MAX_CHARS_SSID)){
        LOGW("Failed to read ssid from storage!");
        load_error = true;
    }

    if(auth_mode != WIFI_AUTH_OPEN) {
        if(!wifi_load_pass(password, MAX_CHARS_PASSWORD)) {
            LOGW("Failed to read password from storage!");
            load_error = true;
        }
    }

    if(!load_error) {
        if(!wifi_set_all(ssid, password, (wifi_auth_mode_t)auth_mode, WIFI_CONTEXT_PRIMARY))
            return false;
        LOGI("Wi-Fi SSID:      %s", wifi_ssid[WIFI_CONTEXT_PRIMARY]);
        if(debug_logs)
            LOGI("Wi-Fi Password:  %s", wifi_pswd[WIFI_CONTEXT_PRIMARY]);
        else
            LOGI("Wi-Fi Password:  ************");
        LOGI("Wi-Fi Auth Mode: %d", wifi_auth_mode[WIFI_CONTEXT_PRIMARY]);
        return true;
    } else {
        DEBUG("Failed to load wifi credentials");
    }

    return false;
}

void wifi_set_max_reconnect_attempts(uint8_t attempts)
{
    max_attempts = attempts;
}

void wifi_set_reconnect_time(int seconds)
{
    wifi_reconnect_time = MAX(seconds, 10);
}


bool wifi_test_wifi(int timeout_ms, uint8_t* error_code)
{
    bool success = false;
    timeout_ms = MAX(10,timeout_ms);

    // copy these
    bool _wifi_enabled = wifi_enabled;
    bool _wifi_should_connect = wifi_should_connect;
    uint8_t _max_attempts = max_attempts;

    // disconnect existing connection
    wifi_disconnect();

    // temporarily set these for the test
    wifi_should_connect = true;
    max_attempts = 0; // 0 = infinite

    if(!config_connection(WIFI_CONTEXT_TEST)) {
        goto end_test;
    }

    // make sure wifi is enabled
    if(!wifi_enabled)
    {
        LOGI("Enabling wifi before test");
        wifi_enable();
    }

    LOGI("Wifi test started, timeout: %d", timeout_ms);
    if(!_wifi_connect())
        goto end_test;

    for(;;)
    {
        if(wifi_connected)
        {
            success = true;
            break;
        }
        if(timeout_ms <= 0) break;
        timeout_ms -= 10;
        delay(10);
    }

end_test:

    if(success) {

        LOGI("Wifi test succeeded");
        if(error_code != NULL) *error_code = WIFI_ERR_SUCCESS;

        // copy to primary
        wifi_set_ssid(wifi_ssid[WIFI_CONTEXT_TEST], WIFI_CONTEXT_PRIMARY);
        wifi_set_password(wifi_pswd[WIFI_CONTEXT_TEST], WIFI_CONTEXT_PRIMARY);
        wifi_set_auth_mode((wifi_auth_mode_t)wifi_auth_mode[WIFI_CONTEXT_TEST], WIFI_CONTEXT_PRIMARY);

        // Let the device stay connected
        // if(!_wifi_enabled) {
        //     // also calls disconnect
        //     wifi_disable();
        // } else if(!_wifi_should_connect) {
        //     wifi_disconnect();
        // }

    } else {

        LOGW("Wifi test failed");
        if(error_code != NULL) *error_code = err_code;

        wifi_disable();

        // re-connect to primary
        if(_wifi_should_connect)
        {
            LOGI("Reconnecting wifi");
            wifi_enable();
            wifi_connect();
        }
        else if(_wifi_enabled)
        {
            wifi_enable();
        }

    }

    // set max_attempts back to what it was orginally
    max_attempts = _max_attempts;
    return success;
}


bool wifi_test_wifi_task(bool* exec_result, int timeout_ms, uint8_t* error_code, void (*post_process_func)())
{
    if(test_task_created) return false;
    int ret = 0;
    test_task_post_process_func = post_process_func;
    test_task_timeout_ms = timeout_ms;
    test_task_error_code = error_code;
    test_task_exec_result = exec_result;
    test_task_action = 1;
    if(!create_wifi_test_task(&ret)) {
        LOGW("Failed to create wifi test task, ret: %d", ret);
        return false;
    }
    return true;
}

bool wifi_list_ap_task(bool* exec_result, void (*post_process_func)())
{
    if(test_task_created) return false;
    int ret = 0;
    test_task_post_process_func = post_process_func;
    test_task_exec_result = exec_result;
    test_task_action = 2;
    if(!create_wifi_test_task(&ret)) {
        LOGW("Failed to create wifi test task, ret: %d", ret);
        return false;
    }
    return true;
}

bool wifi_test_task_running()
{
    return test_task_created;
}

bool wifi_wait_for_connect(int timeout_ms)
{
    if(!wifi_enabled) {
        LOGW("Enable wifi before performing this action");
        return false;
    }

    if(!wifi_should_connect) {
        LOGW("Connect wifi before performing this action");
        return false;
    }

    // if(wifi_status == WIFI_STATUS_NONE) {
    //     LOGW("Init wifi before performing this action");
    //     return false;
    // }

    timeout_ms = MAX(10,timeout_ms);
    //TODO: maybe trigger connection if not currently trying to connect
    for(;;)
    {
        if(wifi_connected) return true;
        if(timeout_ms <= 0) return false;
        timeout_ms -= 10;
        delay(10);
    }
    return false;
}


bool wifi_wait_for_internet(int timeout_ms)
{
    if(!wifi_enabled) {
        LOGW("Enable wifi before performing this action");
        return false;
    }

    if(!wifi_should_connect) {
        LOGW("Connect wifi before performing this action");
        return false;
    }

    // if(wifi_status == WIFI_STATUS_NONE) {
    //     LOGW("Init wifi before performing this action");
    //     return false;
    // }

    timeout_ms = MAX(10,timeout_ms);
    for(;;)
    {
        if(internet_connected) return true;
        if(timeout_ms <= 0) return internet_connected;
        timeout_ms -= 10;
        delay(10);
    }
    return internet_connected;
}


bool wifi_list_ap()
{
    esp_err_t err;
    bool result = true;

    bool _wifi_enabled = wifi_enabled;
    bool _wifi_should_connect = wifi_should_connect;

    if(!wifi_enabled)
    {
        DEBUG("Enabling wifi before scan");
        wifi_enable();
    }

    if(wifi_connecting)
    {
        DEBUG("Stopping wifi connection attempts before scan");
        wifi_disconnect();
    }

    // scan config
    wifi_scan_config_t config = {};
    config.ssid        = NULL;
    config.bssid       = NULL;
    config.channel     = 0;
    config.show_hidden = true;
    config.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    config.scan_time.active.min = 10;
    config.scan_time.active.max = 100;

    DEBUG("Starting scan...");
    uint16_t num_ap = 0;

    err = esp_wifi_scan_start(&config, true);
    if(err != ESP_OK) {
        LOGE("Failed to scan wifi access points, error: 0x%x (%s)", err, esp_err_to_name(err));
        result = false;
        goto end_scan;
    }

    // scan is done, process
    num_accesspoints = 0;

    esp_wifi_scan_get_ap_num(&num_ap);
    LOGI("Num access points found: %u", num_ap);

    if(num_ap > 0) {
        wifi_ap_record_t *records = (wifi_ap_record_t*)calloc(num_ap, sizeof(wifi_ap_record_t));
        err = esp_wifi_scan_get_ap_records(&num_ap, records);

        if(err != ESP_OK) {
            LOGE("Failed to retrieve wifi access point records, error: 0x%x (%s)", err, esp_err_to_name(err));
            free(records);
            result = false;
            goto end_scan;
        }

        memset(accesspoints,0,MAX_NUM_ACCESSPOINTS*sizeof(wifi_accesspoint_t));

        // get unique list
        for(int i = 0; i < num_ap; ++i) {
            if(num_accesspoints < MAX_NUM_ACCESSPOINTS) {
                if(is_ssid_unique_in_list(records[i].ssid) && strlen((char*)records[i].ssid) > 0) {
                    memcpy(accesspoints[num_accesspoints].ssid, records[i].ssid, MAX_CHARS_SSID);
                    accesspoints[num_accesspoints].rssi = records[i].rssi + 127;
                    accesspoints[num_accesspoints].authmode = (wifi_auth_mode_t)records[i].authmode;
                    num_accesspoints++;
                }
            }
        }

        free(records);
        result = true;

        LOGI("Unique SSID Count: %u",num_accesspoints);

        for(int i = 0; i < num_accesspoints; ++i) {
            LOGI("RSSI: %3d, AUTH: %2d, SSID: %s", accesspoints[i].rssi, accesspoints[i].authmode, (char*)accesspoints[i].ssid);
            // DEBUG("RSSI: %3d, AUTH: %2d, SSID: %s", accesspoints[i].rssi, accesspoints[i].authmode, (char*)accesspoints[i].ssid);
        }
    }

end_scan:

    if(!_wifi_enabled) {
        DEBUG("Disabling wifi");
        wifi_disable();
    }

    if(_wifi_should_connect) {
        DEBUG("Reconnecting wifi");
        wifi_connect();
    }

    return result;
}

uint8_t wifi_get_num_accesspoints()
{
    return num_accesspoints;
}


bool wifi_get_ap_info(uint8_t index, wifi_accesspoint_t* ap_info)
{
    if(index >= MAX_NUM_ACCESSPOINTS || index >= num_accesspoints) return false;
    memcpy(ap_info, &accesspoints[index], sizeof(wifi_accesspoint_t));
    return true;
}

WifiStatus wifi_get_status()
{
    return wifi_status;
}

bool wifi_get_internet_status()
{
    return internet_connected;
}

bool wifi_get_ip_addr(char* ret_str)
{
    if(!internet_connected) return false;
    sprintf(ret_str, IPSTR, IP2STR(&ip_addr));
    return true;
}

bool wifi_get_ssid(char* ret_ssid, WifiContext context)
{
    if(context == WIFI_CONTEXT_MAX) return false;
    if(wifi_ssid[context] == 0 || strlen(wifi_ssid[context]) == 0) return false;
    memset(ret_ssid, 0, MAX_CHARS_SSID);
    memcpy(ret_ssid, wifi_ssid[context], strlen(wifi_ssid[context]));
    return true;
}

bool wifi_get_password(char* ret_pswd, WifiContext context)
{
    if(context == WIFI_CONTEXT_MAX) return false;
    if(wifi_pswd[context] == 0 || strlen(wifi_pswd[context]) == 0) return false;
    memset(ret_pswd, 0, MAX_CHARS_PASSWORD);
    memcpy(ret_pswd, wifi_pswd[context], strlen(wifi_pswd[context]));
    return true;
}

void wifi_get_auth_mode(wifi_auth_mode_t* ret_auth_mode, WifiContext context)
{
    if(context == WIFI_CONTEXT_MAX) return;
    *ret_auth_mode = (wifi_auth_mode_t)wifi_auth_mode[context];
}


bool wifi_get_rssi(int8_t* ret_rssi)
{
    if(!wifi_connected) return false;
    wifi_ap_record_t ap_info = {};
    esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);
    if(err != ESP_OK) {
        LOGE("Failed to get rssi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }
    *ret_rssi = ap_info.rssi;
    return true;
}


// ====================================================================
// STATIC FUNCTIONS
// ====================================================================

static bool _wifi_connect()
{
    esp_timer_stop(wifi_reconnect_timer);
    esp_err_t err = esp_wifi_connect();
    if(err == ESP_ERR_WIFI_NOT_STARTED) {
        err_code = WIFI_ERR_START; // TODO
        LOGW("Enable wifi before calling connect");
        return false;
    } else if(err != ESP_OK) {
        err_code = WIFI_ERR_START; // TODO
        LOGE("Failed to connect wifi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }
    return true;
}

static bool config_connection(WifiContext context)
{
    if(context >= WIFI_CONTEXT_MAX) return false;

    esp_err_t err;

    bool _wifi_enabled = wifi_enabled;

    err = wait_for_stop(200);
    if(err != ESP_OK) {
        err_code = WIFI_ERR_START;
        LOGE("Failed to stop wifi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    wifi_config_t wifi_config = {};
    wifi_sta_config_t wifi_sta_config = {};

    uint8_t ssid_len = strlen(wifi_ssid[context]);
    if(ssid_len == 0) {
        err_code = WIFI_ERR_SSID_LEN;
        LOGW("Invalid ssid");
        if(_wifi_enabled) wifi_enable();
        return false;
    }
    memcpy(wifi_sta_config.ssid, wifi_ssid[context], ssid_len);

    if(wifi_auth_mode[context] > WIFI_AUTH_OPEN) {
        uint8_t pswd_len = strlen(wifi_pswd[context]);
        if(pswd_len == 0) {
            err_code = WIFI_ERR_PSWD_LEN;
            LOGW("Invalid password");
            if(_wifi_enabled) wifi_enable();
            return false;
        }
        memcpy(wifi_sta_config.password, wifi_pswd[context], pswd_len);
    }

    wifi_sta_config.scan_method = WIFI_FAST_SCAN;
    wifi_sta_config.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

    memcpy(&wifi_config.sta, &wifi_sta_config, sizeof(wifi_sta_config));

    LOGI("ssid: %s", wifi_config.sta.ssid);
    LOGI("authmode: %u",wifi_auth_mode[context]);

    if(wifi_auth_mode[context] > WIFI_AUTH_OPEN) {
        if(debug_logs)
            LOGI("pswd: %s", wifi_config.sta.password);
        else
            LOGI("pswd: ************");
    } 

    err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    if(err != ESP_OK) {
        if(err == ESP_ERR_WIFI_PASSWORD)
        {
            err_code = WIFI_ERR_PSWD;
            LOGE("Invalid password entered , error: 0x%x (%s)", err, esp_err_to_name(err));
        }
        else
        {
            err_code = WIFI_ERR_CONFIG;
            LOGE("Failed to set wifi config, error: 0x%x (%s)", err, esp_err_to_name(err));
        }
        return false;
    }

    err = wait_for_start(200);
    if(err != ESP_OK) {
        err_code = WIFI_ERR_START;
        LOGE("Failed to start wifi, error: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    DEBUG("Successful config_connection");
    connect_attempts = 0;
    return true;
}


static esp_err_t wait_for_start(int ms)
{
    if(wifi_enabled) return ESP_OK;
    DEBUG("Enabling wifi");
    esp_err_t err = esp_wifi_start();
    if(err != ESP_OK) return err;
    ms = MAX(ms/10,0);
    for(int i = 0; i < ms; i++) {
        if(wifi_enabled) return ESP_OK;
        delay(10);
    }
    return ESP_FAIL;
}

static esp_err_t wait_for_stop(int ms)
{
    if(!wifi_enabled) return ESP_OK;
    DEBUG("Disabling wifi");
    esp_err_t err = esp_wifi_stop();
    if(err != ESP_OK) return err;
    ms = MAX(ms/10,0);
    for(int i = 0; i < ms; i++) {
        if(!wifi_enabled) return ESP_OK;
        delay(10);
    }
    return ESP_FAIL;
}


#if IDF_VERSION == 4
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if(event_base == WIFI_EVENT) {
        switch(event_id) {
#else
static esp_err_t wifi_event_handler(void *ctx, system_event_t *event) {
        switch(event->event_id) {
#endif
            case EVT_SCAN_DONE: {
                DEBUG("[WIFI EVENT] Scan done");
            } break;

            case EVT_STA_STOP: {
                DEBUG("[WIFI EVENT] Station stop");
                wifi_enabled = false;
                wifi_connected = false;
                wifi_connecting = false;
                internet_connected = false;
                update_wifi_status();
            } break;

            case EVT_STA_START: {
                DEBUG("[WIFI EVENT] Station start");
                wifi_enabled = true;
                update_wifi_status();
            } break;

            case EVT_STA_CONNECTED: {
                LOGI("Station connected event");
                wifi_connected = true;
                wifi_connecting = false;
                connect_attempts = 0;
                update_wifi_status();
            } break;

            case EVT_STA_DISCONNECTED: {

                wifi_connected = false;
                internet_connected = false;

                if(!wifi_should_connect)
                {
                    LOGI("Station disconnected event, reason: 'disconnect called by user'");
                    update_wifi_status();
                    break;
                }

                if(!wifi_enabled)
                {
                    LOGI("Station disconnected event, reason: 'wifi disabled by user'");
                    update_wifi_status();
                    break;
                }

#if IDF_VERSION == 4
                //components/esp_wifi/include/esp_wifi_types.h
                wifi_event_sta_disconnected_t* event = (wifi_event_sta_disconnected_t*)event_data;
                uint8_t reason = event->reason;
#else
                uint8_t reason = event->event_info.disconnected.reason;
#endif
                err_code = convert_wifi_disconnect_reason(reason);

                // avoid wrapping
                if(connect_attempts >= 254) connect_attempts = 254;
                connect_attempts++;

                LOGW("Station disconnected event, reason: %u (attempt: %u, max attempts: %u)", reason, connect_attempts, max_attempts);

                if(max_attempts == 0 || connect_attempts < max_attempts)
                {
                    _wifi_connect();
                    wifi_connecting = true;
                    update_wifi_status();
                }
                else
                {
                    // @SOFTWARE_REQ (P_303)
                    // The device reconnects to internet
                    
                    // update status to not connected
                    LOGI("Exceeded max connection attempts");
                    wifi_connecting = false;
                    connect_attempts = 0;
                    update_wifi_status();

                    uint64_t timeout_us = wifi_reconnect_time*1000000;
                    esp_timer_stop(wifi_reconnect_timer);
                    esp_err_t err = esp_timer_start_once(wifi_reconnect_timer, timeout_us);
                    if(err != ESP_OK)
                    {
                        LOGE("Failed to start wifi reconnection timer, error: 0x%x (%s)", err, esp_err_to_name(err));
                        // continuously try and connect
                        max_attempts = 0;
                        _wifi_connect();
                    }
                    else
                    {
                        LOGI("Reconnection timer started for %.2f minute(s) (%d seconds)", wifi_reconnect_time/60.0f, wifi_reconnect_time);
                    }

                }

            } break;

#if IDF_VERSION == 4
            default: {
                DEBUG("[WIFI EVENT] id: %d", event_id);
            } break;

        }
    } else if(event_base == IP_EVENT) {

        switch(event_id) {
#endif

            case EVT_GOT_IP: {
                DEBUG("[IP EVENT] Got IP");
                internet_connected = true;
#if IDF_VERSION == 4
                ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
                LOGI("ip address: " IPSTR, IP2STR(&event->ip_info.ip));
                memcpy(&ip_addr, &event->ip_info.ip, sizeof(ip_addr));
#else
                DEBUG("ip address: %s", ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
                memcpy(&ip_addr, &event->event_info.got_ip.ip_info.ip, sizeof(ip_addr));
#endif
                update_wifi_status();
                time_update_time(0);
            } break;

            case EVT_LOST_IP: {
                DEBUG("[IP EVENT] Lost IP");
                internet_connected = false;
                update_wifi_status();
            } break;

#if IDF_VERSION == 4
            default: {
                DEBUG("[IP EVENT] id: %d", event_id);
            } break;
#else
            default: {
                DEBUG("[WIFI EVENT] id: %d", event->event_id);
            } break;
#endif
        }
#if IDF_VERSION == 4
    }
#else
    return ESP_OK;
#endif
}

static void IRAM_ATTR wifi_reconnect_routine(void* arg)
{
    DEBUG("wifi_reconnect_routine");
    wifi_connect();
}

static uint8_t convert_wifi_disconnect_reason(uint8_t reason)
{
    switch(reason) {
        case WIFI_REASON_NO_AP_FOUND:            // 201
            // likely SSID is incorrect
            return 6;
        case WIFI_REASON_AUTH_FAIL:              // 202
        case WIFI_REASON_HANDSHAKE_TIMEOUT:      // 204
        case WIFI_REASON_AUTH_EXPIRE:            // 2
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT: // 15
            // likely password is incorrect
            return 7;
        default:
            // other error
            return 255;
    }
    return 255;
}

static bool is_ssid_unique_in_list(uint8_t* ssid)
{
    for(int i = 0; i < MAX_NUM_ACCESSPOINTS; ++i) {
        if(memcmp(ssid, accesspoints[i].ssid, MAX_CHARS_SSID) == 0) return false;
    }
    return true;
}

static void update_wifi_status()
{
    WifiStatus prior_status = wifi_status;

    if(internet_connected) {
        wifi_status = WIFI_STATUS_CONNECTED;
    } else if(wifi_connected) {
        wifi_status = WIFI_STATUS_CONNECTED_NO_INTERNET;
    } else if(wifi_connecting) {
        wifi_status = WIFI_STATUS_CONNECTING;
    } else if(wifi_enabled) {
        wifi_status = WIFI_STATUS_NOT_CONNECTED;
    } else {
        wifi_status = WIFI_STATUS_DISABLED;
    }

    if(wifi_status != prior_status)
    {
        LOGI("wifi status: %d (%s)", wifi_status, wifi_status_str[wifi_status]);
    }
}

static void wifi_test_task(void* arg)
{
    test_task_created = true;
    LOGI("Entered wifi test task, action: %u", test_task_action);

    if(test_task_action == 1)
    {
        uint8_t err_code = 0;
        bool result = wifi_test_wifi(test_task_timeout_ms, &err_code);
        if(test_task_error_code != NULL) *test_task_error_code = err_code;
        if(test_task_exec_result != NULL) *test_task_exec_result = result;

        if(result)
        {
            if(!wifi_store_ssid(wifi_ssid[WIFI_CONTEXT_TEST])) {
                LOGE("Failed to store ssid");
            }

            if(!wifi_store_pass(wifi_pswd[WIFI_CONTEXT_TEST])) {
                LOGE("Failed to store password");
            }

            if(!wifi_store_auth(wifi_auth_mode[WIFI_CONTEXT_TEST])) {
                LOGE("Failed to store auth mode");
            }

        }

        if(test_task_post_process_func != NULL)
        {
            test_task_post_process_func();
            test_task_post_process_func = NULL;
        }

    }
    else if(test_task_action == 2)
    {
        bool result = wifi_list_ap();
        if(test_task_exec_result != NULL) *test_task_exec_result = result;
        if(test_task_post_process_func != NULL)
        {
            test_task_post_process_func();
            test_task_post_process_func = NULL;
        }
    }

    LOG_TASK_HWM();
    test_task_action = 0;
    test_task_created = false;
    vTaskDelete(NULL);
}

static bool create_wifi_test_task(int* ret)
{
    if(test_task_created) return true;
    LOGI("[Creating Wifi Task] Stack size: %d, Priority: %d, Core: %d", test_task_config.stack_size, test_task_config.priority, test_task_config.core);
    int _ret = xTaskCreatePinnedToCore(wifi_test_task, "wifi_test_task", test_task_config.stack_size, NULL, test_task_config.priority, &test_task_config.handle, test_task_config.core);
    if(ret != NULL) *ret = _ret;
    if(_ret != pdPASS)
    {
        return false;
    }
    return true;
}
 
