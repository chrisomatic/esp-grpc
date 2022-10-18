#include "lightyear.h"
#include "lightyear_wifi.h"
#include "lightyear_util.h"

#include "grpc.h"

#include "esp_random.h"
#include "esp_tls.h"

#include <nghttp2/nghttp2.h>
#include <http_parser.h>
#include <netdb.h>


// ====================================================================
// DEFINES & MACROS
// ====================================================================

#define GRPC_DEBUG 1

#if GRPC_DEBUG
#define DLOG(f, ...) LOGI(f,##__VA_ARGS__)
#else
#define DLOG(f, ...)
#endif

#define MAKE_NV(NAME, VALUE) \
{ \
    (uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE), \
        NGHTTP2_NV_FLAG_NONE \
}

/** Flag indicating receive stream is reset */
#define DATA_RECV_RST_STREAM      1
/** Flag indicating frame is completely received  */
#define DATA_RECV_FRAME_COMPLETE  2

#define MESSAGE_PREFIX_SIZE 5
#define MAX_GRPC_BUFFER_SIZE 1024

// ====================================================================
// TYPES
// ====================================================================

typedef int (*_frame_data_recv_cb_t)(const char* data, size_t len, int flags);
typedef int (*_putpost_data_cb_t)(char *data, size_t len, uint32_t *data_flags);

typedef struct
{
    nghttp2_session* http2_sess;   /*!< Pointer to the HTTP2 session handle */
    char* hostname;     /*!< The hostname we are connected to */
    struct esp_tls* http2_tls;    /*!< Pointer to the TLS session handle */
} grpc_handle_t;

typedef struct
{
    uint8_t buf[MAX_GRPC_BUFFER_SIZE];
    size_t len;
} GRPCBuffer;

// ====================================================================
// STATIC VARS
// ====================================================================

static TaskHandle_t http2_task_handle = NULL;
static TaskHandle_t grpc_task_handle = NULL;

static grpc_conn_data_t conn_data = {0};
static grpc_init_t cfg = {0};
static grpc_handle_t hd = {0};


static struct
{
    bool initialized:1;
    bool conn_configured:1;

    bool trigger_connect:1; // also SHOULD connect
    bool connected:1;

    bool message_pending:1;
    bool ping_pending:1;

} bools;


static int64_t ping_recv_time = 0;   //recv time
static uint8_t ping_data[8] = {0};

static GRPCBuffer buffer_recv;
static GRPCBuffer buffer_send;

// ====================================================================
// STATIC PROTOS
// ====================================================================

static bool grpc_task_start_connection();
static void grpc_task();

static void handle_disconnect();
static void http2_task();
static bool http2_execute();


static bool _connect();

static void free_handle();
static int send_post_data(char *buf, size_t length, uint32_t *data_flags);
static ssize_t _data_provider_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf,size_t length, uint32_t *data_flags,nghttp2_data_source *source, void *user_data);

static ssize_t callback_send(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
static ssize_t callback_recv(nghttp2_session* session, uint8_t* buf, size_t length, int flags, void* user_data);
static int callback_on_frame_send(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
static int callback_on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
static int callback_on_stream_close(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data);
static int callback_on_data_chunk_recv(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data);
static int callback_on_header(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);

static const char* frame_type_to_str(int type);


// ====================================================================
// GLOBAL FUNCTIONS
// ====================================================================

bool grpc_init(grpc_init_t config)
{
    int ret = xTaskCreatePinnedToCore(http2_task, "http2_task", config.http2_stack_size, NULL, config.http2_prio, &http2_task_handle, config.http2_core);
    if(ret != pdPASS)
    {
        LOGE("Failed to create http2 task, ret: %d", ret);
        return false;
    }

    ret = xTaskCreatePinnedToCore(grpc_task, "grpc_task", config.grpc_stack_size, NULL, config.grpc_prio, &grpc_task_handle, config.grpc_core);
    if(ret != pdPASS)
    {
        LOGE("Failed to create GRPC task, ret: %d", ret);
        return false;
    }

    memcpy(&cfg, &config, sizeof(grpc_init_t));
    vTaskSuspend(http2_task_handle);
    bools.initialized = true;
    return true;
}

bool grpc_configure_connection(grpc_conn_data_t connection_data)
{
    if(!bools.initialized) return false;
    if(bools.conn_configured) return false;

    memcpy(&conn_data, &connection_data, sizeof(grpc_conn_data_t));
    bools.conn_configured = true;
    return true;
}


bool grpc_connect()
{
    if(!bools.initialized) return false;
    if(!bools.conn_configured) return false;
    if(bools.connected) return true;

    bools.trigger_connect = true;
    return true;
}

bool grpc_connected()
{
    return bools.connected;
}

bool grpc_wait_for_connection(int timeout_ms)
{
    for(;;)
    {
        if(bools.connected) return true;
        if(timeout_ms <= 0) return bools.connected;
        timeout_ms -= 10;
        delay(10);
    }
}

bool gprc_send_message_pending()
{
    return bools.message_pending;
}

bool grpc_ping(int timeout_ms, int64_t* _ping_time)
{
    if(!bools.conn_configured) return false;
    if(hd.http2_sess == NULL) return false;

    esp_fill_random(ping_data, 8);
    bools.ping_pending = true;
    LOGI("Ping data:");
    LOGI_HEX(ping_data, 8);

    int64_t sent_time = esp_timer_get_time();
    int ret = nghttp2_submit_ping(hd.http2_sess, NGHTTP2_FLAG_NONE, (const uint8_t*)ping_data);
    if(ret != 0)
    {
        LOGE("Submit ping failed, ret: %d (%s)", ret, nghttp2_strerror(ret));
        bools.ping_pending = false;
        return false;
    }

    for(;;)
    {
        if(!bools.ping_pending) break;
        if(timeout_ms < 0) break;
        timeout_ms -= 10;
        delay(10);
    }

    if(!bools.ping_pending)
    {
        if(_ping_time != NULL)
        {
            *_ping_time = ping_recv_time - sent_time;
        }
        return true;
    }

    return false;
}

bool grpc_call_proc(char* path, char* proc, uint8_t* data, uint32_t len)
{
    if(hd.http2_sess == NULL) return false;
    if(!bools.connected) return false;

    int max_len = (MAX_GRPC_BUFFER_SIZE - MESSAGE_PREFIX_SIZE);
    if(len >= max_len)
    {
        LOGE("Specified Length of %d exceeds the maximum allowed data size of %d",len,max_len);
        return false;
    }

    // printf("bools.message_pending is %s\n", BOOLSTR(bools.message_pending));
    for(;;)
    {
        // wait for prior message to complete
        if(!bools.message_pending)
            break;

        delay(10);
    }
    // printf("bools.message_pending = true\n");
    bools.message_pending = true;

    memcpy(buffer_send.buf+MESSAGE_PREFIX_SIZE,data,len);
    buffer_send.len = len;

    // Necessary for gRPC Message for DATA frame
    // https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
    uint8_t* ml = (uint8_t*)&buffer_send.len;
    buffer_send.buf[0] = 0x0; // no compression
    buffer_send.buf[1] = *(ml+3); // big-endian
    buffer_send.buf[2] = *(ml+2);
    buffer_send.buf[3] = *(ml+1);
    buffer_send.buf[4] = *(ml+0);

    char content_length[8+1] = {0};
    snprintf(content_length, 8,"%d",len+MESSAGE_PREFIX_SIZE);

    char full_path[128+1] = {0};
    snprintf(full_path, 128,"%s/%s",path,proc);

    const nghttp2_nv nva[] = { 
        MAKE_NV(":method", "POST"),
        MAKE_NV(":scheme", "https"),
        MAKE_NV(":authority", hd.hostname),
        MAKE_NV(":path", full_path),
        MAKE_NV("content-type", "application/grpc+proto"),
        MAKE_NV("content-length", content_length),
    };

    nghttp2_data_provider dp;
    dp.read_callback = _data_provider_cb;
    dp.source.ptr = send_post_data;

    int ret = nghttp2_submit_request(hd.http2_sess, NULL, nva, sizeof(nva) / sizeof(nva[0]), &dp, NULL);

    if(ret < 0)
    {
        LOGE("Submit Request failed: %d", ret);
        bools.message_pending = false;
        return false;
    }

    return true;
}

const char* grpc_status_code_to_str(GRPCStatusCode sc)
{
    static const char* sc_str[] = {"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"};
    int num_sc = sizeof(sc_str)/sizeof(sc_str[0]);
    if(sc < 0 || sc >= num_sc) return "UNKNOWN";
    return sc_str[sc];
}

// ====================================================================
// STATIC FUNCTIONS
// ====================================================================

static bool grpc_task_start_connection()
{
    if(!bools.conn_configured)
    {
        return false;
    }

    if(bools.connected)
    {
        LOGW("you shouldn't be here");
        return false;
    }

    if(!wifi_get_internet_status())
    {
        return false;
    }

    if(bools.trigger_connect)
    {
        bool success = _connect();
        return success;
    }

    return false;
}

static void grpc_task()
{
    LOGI("Entered GRPC task");

    for(;;)
    {
        bool connected = grpc_task_start_connection();

        if(!connected)
        {
            delay(1000);
            continue;
        }

        for(;;)
        {

            if(!bools.connected) break;
            if(hd.http2_sess == NULL) break;

            // TODO: process data

            delay(100);
        }

        vTaskSuspend(http2_task_handle);


    }

    vTaskDelete(NULL);
}

static void handle_disconnect()
{

    if(bools.connected)
    {
        LOGW("DISCONNECTED");
    }

    bools.connected = false;
    // free_handle();   // not safe here
}

static void http2_task()
{
    LOGI("Entered http2 task");

    for(;;)
    {
        if(hd.http2_sess != NULL)
        {
            if(!http2_execute())
            {
                LOGE("Error in send/receive");
                handle_disconnect();
            }
            delay(10);
        }
        else
        {
            delay(100);
        }
    }

    vTaskDelete(NULL);
}

static bool http2_execute()
{
    if(hd.http2_sess == NULL) return false;
    int ret = nghttp2_session_send(hd.http2_sess);
    if(ret != 0)
    {
        LOGE("[sh2-execute] HTTP2 session send failed, ret: %d (%s)", ret, nghttp2_strerror(ret));
        return false;
    }

    if(hd.http2_sess == NULL) return false;
    ret = nghttp2_session_recv(hd.http2_sess);
    if(ret != 0)
    {
        LOGE("[sh2-execute] HTTP2 session recv failed, ret: %d (%s)", ret, nghttp2_strerror(ret));
        return false;
    }

    return true;
}



static bool _connect()
{
    bools.connected = false;
    free_handle();
    memset(&hd, 0, sizeof(grpc_handle_t));

    const char* proto[] = {"h2", NULL};
    esp_tls_cfg_t tls_cfg = {0};
    tls_cfg.alpn_protos = proto;
    tls_cfg.cacert_buf = (const unsigned char*)conn_data.ca;
    tls_cfg.cacert_bytes = strlen(conn_data.ca)+1;
    tls_cfg.non_block = true;
    tls_cfg.timeout_ms = 10 * 1000;

    if((hd.http2_tls = esp_tls_conn_http_new(conn_data.uri, &tls_cfg)) == NULL)
    {
        LOGE("esp-tls connection failed");
        goto error;
    }

    struct http_parser_url u;
    http_parser_url_init(&u);
    http_parser_parse_url(conn_data.uri, strlen(conn_data.uri), 0, &u);
    hd.hostname = strndup(&conn_data.uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);

    LOGI("Setting up HTTP2 connection with uri: %s", conn_data.uri);
    nghttp2_session_callbacks* callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, callback_send);
    nghttp2_session_callbacks_set_recv_callback(callbacks, callback_recv);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, callback_on_frame_send);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, callback_on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, callback_on_stream_close);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, callback_on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, callback_on_header);

    int ret = nghttp2_session_client_new(&hd.http2_sess, callbacks, &hd);
    if(ret != 0)
    {
        LOGE("New http2 session failed, ret: %d (%s)", ret, nghttp2_strerror(ret));
        nghttp2_session_callbacks_del(callbacks);
        goto error;
    }
    nghttp2_session_callbacks_del(callbacks);

    /* Create the SETTINGS frame */
    ret = nghttp2_submit_settings(hd.http2_sess, NGHTTP2_FLAG_NONE, NULL, 0);
    if(ret != 0)
    {
        LOGE("Submit settings failed, ret: %d (%s)", ret, nghttp2_strerror(ret));
        goto error;
    }

    vTaskResume(http2_task_handle);

    int timeout_ms = 10000;
    for(;;)
    {
        if(bools.connected) return true;

        if(!wifi_get_internet_status())
        {
            LOGW("Lost internet connection");
            goto error;
        }

        delay(10);
        timeout_ms -= 10;
        if(timeout_ms <= 0)
        {
            goto error;
        }
    }

    return true;

error:
    free_handle();
    vTaskSuspend(http2_task_handle);
    return false;
}

static void free_handle()
{
    LOGI("Freeing handle");

    if(hd.http2_sess)
    {
        nghttp2_session_del(hd.http2_sess);
        hd.http2_sess = NULL;
    }

    if(hd.http2_tls)
    {
        esp_tls_conn_delete(hd.http2_tls);
        hd.http2_tls = NULL;
    }

    if(hd.hostname)
    {
        free(hd.hostname);
        hd.hostname = NULL;
    }
}

static ssize_t _data_provider_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf,size_t length, uint32_t *data_flags,nghttp2_data_source *source, void *user_data)
{
    _putpost_data_cb_t data_cb = source->ptr;
    return (*data_cb)((char *)buf, length, data_flags);
}

// callback for sending data
static int send_post_data(char *buf, size_t length, uint32_t *data_flags)
{
    int copylen = buffer_send.len+MESSAGE_PREFIX_SIZE;
    if (copylen < length) {
        LOGI("[SEND] Sending %d bytes", copylen);
        memcpy(buf, buffer_send.buf, buffer_send.len+MESSAGE_PREFIX_SIZE);
    } else {
        copylen = 0;
    }

    // printf("bools.message_pending = false\n");
    bools.message_pending = false;

    (*data_flags) |= NGHTTP2_DATA_FLAG_EOF;
    return copylen;
}

static ssize_t callback_send(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
    int copy_offset = 0;
    int pending_data = length;
    int rv = 0;

    /* Send data in 1000 byte chunks */
    while(copy_offset != length)
    {
        int chunk_len = pending_data > 1000 ? 1000 : pending_data;

        int subrv = esp_tls_conn_write(hd.http2_tls, data+copy_offset, chunk_len);

        if(subrv <= 0)
        {
            if(subrv == ESP_TLS_ERR_SSL_WANT_READ || subrv == ESP_TLS_ERR_SSL_WANT_WRITE) {
                subrv = NGHTTP2_ERR_WOULDBLOCK;
            } else {
                subrv = NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        }

        if(subrv <= 0)
        {
            if(copy_offset == 0) {
                /* If no data is transferred, send the error code */
                rv = subrv;
            }
            break;
        }
        copy_offset += subrv;
        pending_data -= subrv;
        rv += subrv;
    }
    return rv;
}

static ssize_t callback_recv(nghttp2_session* session, uint8_t* buf, size_t length, int flags, void* user_data)
{
    int rv = esp_tls_conn_read(hd.http2_tls, (char*)buf, (int)length);
    if(rv < 0)
    {
        if(rv == ESP_TLS_ERR_SSL_WANT_READ || rv == ESP_TLS_ERR_SSL_WANT_WRITE) {
            rv = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    else if(rv == 0)
    {
        rv = NGHTTP2_ERR_EOF;
    }
    return rv;
}

static int callback_on_frame_send(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
    DLOG("[frame-send] frame type %s", frame_type_to_str(frame->hd.type));
    switch(frame->hd.type)
    {
        case NGHTTP2_HEADERS:
        {
            if(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id))
            {
                DLOG("[frame-send] C ----------------------------> S (HEADERS)");
                DLOG("[frame-send] headers nv-len = %d", frame->headers.nvlen);
                const nghttp2_nv* nva = frame->headers.nva;
                for(size_t i = 0; i < frame->headers.nvlen; ++i)
                {
                    DLOG("[frame-send] %s : %s", nva[i].name, nva[i].value);
                }
            }
        } break;

        case NGHTTP2_PING:
        {
        } break;
    }
    return 0;
}

static int callback_on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
    int64_t t = esp_timer_get_time();

    DLOG("[frame-recv][sid: %d] frame type: %d (%s)", frame->hd.stream_id, frame->hd.type, frame_type_to_str(frame->hd.type));

    switch(frame->hd.type)
    {
        case NGHTTP2_SETTINGS:
        {
            // const nghttp2_settings* p = &frame->settings;
            if(!bools.connected)
            {
                LOGI("CONNECTED");
                bools.connected = true;
            }
        } break;

        case NGHTTP2_GOAWAY:
        {
            // const nghttp2_goaway* p = &frame->goaway;
            handle_disconnect();
        } break;

        case NGHTTP2_PING:
        {
            const nghttp2_ping* p = &frame->ping;

            if(bools.ping_pending)
            {
                LOGI_HEX(p->opaque_data, 8);
                bool match = memcmp(p->opaque_data, ping_data, 8) == 0;
                if(match)
                {
                    bools.ping_pending = false;
                    ping_recv_time = t;
                }
            }
        } break;

        case NGHTTP2_WINDOW_UPDATE:
        {
            const nghttp2_window_update* w = &frame->window_update;

            LOGI("[Window Size] %d", w->window_size_increment);

        } break;

        default: break;
    }

    return 0;
}

static int callback_on_stream_close(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
{
    DLOG("[stream-close][sid %d]", stream_id);
    LOGI("[RECV] Stream Closed");
    return 0;
}

static int callback_on_data_chunk_recv(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
{
    DLOG("[data-chunk-recv][sid:%d] %lu bytes", stream_id, (unsigned long int)len);

    if (len) {
        LOGI("[RECV] %.*s", len, data);
        LOGI_HEX(data,len);

        buffer_recv.len = len - MESSAGE_PREFIX_SIZE;
        memcpy(buffer_recv.buf, data+MESSAGE_PREFIX_SIZE, buffer_recv.len);
    }
    return 0;
}

static int callback_on_header(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
    DLOG("[hdr-recv][sid:%d] %s : %s", frame->hd.stream_id, name, value);

    if(STR_EQUAL((char*)name, "grpc-status"))
    {
        int sc = atoi((const char*)value);
        LOGI("[hdr-recv] GRPC Status: %s (%d)", grpc_status_code_to_str((GRPCStatusCode)sc), sc);
    }

    return 0;
}

static const char* frame_type_to_str(int type)
{
    switch(type)
    {
        case NGHTTP2_HEADERS: return "HEADERS";
        case NGHTTP2_RST_STREAM: return "RST_STREAM";
        case NGHTTP2_GOAWAY: return "GOAWAY";
        case NGHTTP2_DATA: return "DATA";
        case NGHTTP2_SETTINGS: return "SETTINGS";
        case NGHTTP2_PUSH_PROMISE: return "PUSH_PROMISE";
        case NGHTTP2_PING: return "PING";
        case NGHTTP2_WINDOW_UPDATE: return "WINDOW_UPDATE";
        default: return "other";
    }
}
