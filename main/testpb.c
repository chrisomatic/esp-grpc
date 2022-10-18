// lightyear
#include "lightyear.h"
#include "lightyear_util.h"
#include "lightyear_time.h"

// Protobuffer encode/decode support
#include "pb_common.h"
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

// Proto-generated files
// add proto header files here...
#include "generated/test.pb.h"

#include "testpb.h"

// ====================================================================
// DEFINES & MACROS
// ====================================================================

#define PB_GLUER(a,b) a##b

#define PB_SET_STR(pb_struct_ptr, field, val)    \
    pb_write_string_val(&pb_struct_ptr->field.value, val); \
    pb_struct_ptr->PB_GLUER(has_,field) = true;

#define PB_SET_NUM(pb_struct_ptr, field, val)    \
    pb_struct_ptr->field.value = val; \
    pb_struct_ptr->PB_GLUER(has_,field) = true;

// ====================================================================
// PROTOTYPES
// ====================================================================

static int _encode(const pb_msgdesc_t *fields, const void* src_struct, uint8_t* buf, int len);
static void _decode(uint8_t* buf, int len, Message* cbs);

static bool write_string(pb_ostream_t *stream, const pb_field_iter_t *field, void * const *arg);
static bool read_string(pb_istream_t *stream, const pb_field_iter_t *field, void **arg);

static void map_cloud_brush_session_to_pb(Message* bs, entpb_BrushingSession* pb_s);

static inline void pb_write_string_val(pb_callback_t* f, char* s){ f->funcs.encode = write_string; f->arg = s;}
static void print_cbs(Message* cbs);

// ====================================================================
// GLOBAL FUNCS
// ====================================================================

int testpb_message_create(Message* cbs, uint8_t* buf, int len)
{
    memset(buf,0,len);
    entpb_BrushingSession session = entpb_BrushingSession_init_zero;

    map_cloud_brush_session_to_pb(cbs, &session);

    entpb_CreateBrushingSessionRequest request;
    request.has_brushing_session = true;
    memcpy(&request.brushing_session,&session, sizeof(entpb_BrushingSession));

    int bytes_written = _encode(entpb_CreateBrushingSessionRequest_fields, &request, buf, len);

    return bytes_written;
}

int testpb_message_get(char* id, uint8_t* buf, int len)
{
    memset(buf,0,len);
    entpb_GetBrushingSessionRequest request = entpb_GetBrushingSessionRequest_init_zero;

    request.id.funcs.encode = write_string;
    request.id.arg = id;
    request.view = entpb_GetBrushingSessionRequest_View_BASIC;

    int bytes_written = _encode(entpb_GetBrushingSessionRequest_fields, &request, buf, len);

    return bytes_written;
}

// ====================================================================
// LOCAL FUNCS
// ====================================================================

static int _encode(const pb_msgdesc_t *fields, const void* src_struct, uint8_t* buf, int len)
{
    pb_ostream_t stream = pb_ostream_from_buffer(buf, len);

    bool status = pb_encode(&stream, fields, src_struct);

    if(!status)
    {
        LOGE("Encoding failed: %s", PB_GET_ERROR(&stream));
        return 0;
    }

    LOGI("Encoding Succeeded (%d bytes)",stream.bytes_written);

    return stream.bytes_written;
}

static void _decode(uint8_t* buf, int len, Message* cbs)
{
    entpb_BrushingSession session = entpb_BrushingSession_init_zero;

    BrushSession bs = {0};
    cbs->bs = &bs;

    session.consumer_id.arg = cbs->consumer_id;
    session.id.arg = cbs->session_uuid;
    session.device_id.arg = cbs->brush_device_id;
    session.thing_name.value.arg = cbs->thing_name;
    session.device_type.value.arg = cbs->brush_device_type;
    session.parent_device_id.value.arg = cbs->device_id;
    session.parent_device_type.value.arg = cbs->parent_device_type;
    session.session_client.value.arg = cbs->session_client;
    session.client_version.value.arg = cbs->client_version;
    session.operating_system.value.arg = cbs->operating_system;
    session.operating_system_version.value.arg = cbs->operating_system_version;
    session.primary_brushing_mode.value.arg = cbs->brushing_mode;
    session.pressure_distribution.value.arg = bs.pressure_distribution_str;
    session.zoned_brush_time.value.arg = cbs->zoned_brush_time;
    session.zoned_pressure_time.value.arg = cbs->zoned_pressure_time;
    session.session_type.value.arg = cbs->session_type;

    session.consumer_id.funcs.decode = read_string;
    session.id.funcs.decode = read_string;
    session.device_id.funcs.decode = read_string;
    session.thing_name.value.funcs.decode = read_string;
    session.device_type.value.funcs.decode = read_string;
    session.parent_device_id.value.funcs.decode = read_string;
    session.parent_device_type.value.funcs.decode = read_string;
    session.session_client.value.funcs.decode = read_string;
    session.client_version.value.funcs.decode = read_string;
    session.operating_system.value.funcs.decode = read_string;
    session.operating_system_version.value.funcs.decode = read_string;
    session.primary_brushing_mode.value.funcs.decode = read_string;
    session.pressure_distribution.value.funcs.decode = read_string;
    session.zoned_brush_time.value.funcs.decode = read_string;
    session.zoned_pressure_time.value.funcs.decode = read_string;
    session.session_type.value.funcs.decode = read_string;
    
    pb_istream_t stream = pb_istream_from_buffer(buf,len);
    bool status = pb_decode(&stream, entpb_BrushingSession_fields, &session);
    
    if (!status)
    {
        LOGE("Decoding failed: %s", PB_GET_ERROR(&stream));
        return;
    }

    print_cbs(cbs);
}

static bool write_string(pb_ostream_t *stream, const pb_field_iter_t *field, void * const *arg)
{
    const char* str = (const char*)(*arg);

    if(!str)
    {
        LOGE("str is null\n");
        return false;
    }

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    return pb_encode_string(stream, (uint8_t*)str, strlen(str));
}

static bool read_string(pb_istream_t *stream, const pb_field_iter_t *field, void **arg)
{
    char *str = (char*)(*arg);
    return pb_read(stream, (uint8_t*)str, stream->bytes_left);
}

static void map_cloud_brush_session_to_pb(Message* cbs, entpb_BrushingSession* pb_s)
{
    BrushSession* bs = cbs->bs;

    // required
    pb_write_string_val(&pb_s->consumer_id  ,cbs->consumer_id);
    pb_write_string_val(&pb_s->id           ,cbs->session_uuid);
    pb_write_string_val(&pb_s->device_id    ,cbs->brush_device_id);

    // strings
    PB_SET_STR(pb_s, thing_name               ,cbs->thing_name);
    PB_SET_STR(pb_s, device_type              ,cbs->parent_device_type);
    PB_SET_STR(pb_s, parent_device_id         ,cbs->device_id);
    PB_SET_STR(pb_s, parent_device_type       ,cbs->parent_device_type);
    PB_SET_STR(pb_s, session_client           ,cbs->session_client);
    PB_SET_STR(pb_s, client_version           ,cbs->client_version);
    PB_SET_STR(pb_s, operating_system         ,cbs->operating_system);
    PB_SET_STR(pb_s, operating_system_version ,cbs->operating_system_version);
    PB_SET_STR(pb_s, primary_brushing_mode    ,cbs->brushing_mode);
    PB_SET_STR(pb_s, pressure_distribution    ,bs->pressure_distribution_str);
    PB_SET_STR(pb_s, zoned_brush_time         ,cbs->zoned_brush_time);
    PB_SET_STR(pb_s, zoned_pressure_time      ,cbs->zoned_pressure_time);
    PB_SET_STR(pb_s, session_type             ,cbs->session_type);

    // nums
    PB_SET_NUM(pb_s, handle_session_id    ,bs->session_id);
    PB_SET_NUM(pb_s, battery_level        ,bs->battery_level);
    PB_SET_NUM(pb_s, brushing_duration    ,bs->brushing_duration);
    PB_SET_NUM(pb_s, brush_model          ,bs->device_type);
    PB_SET_NUM(pb_s, on_event_count       ,bs->num_on_events);
    PB_SET_NUM(pb_s, pressure_event_count ,bs->num_high_pressure);
    PB_SET_NUM(pb_s, pressure_duration    ,cbs->pressure_duration);
    PB_SET_NUM(pb_s, gateway_model        ,cbs->gateway_model);
    PB_SET_NUM(pb_s, brush_score          ,bs->brush_score);
    PB_SET_NUM(pb_s, coverage_percentage  ,cbs->coverage_percentage);

    // time
    pb_s->session_start_time.seconds = bs->session_timestamp;
}

