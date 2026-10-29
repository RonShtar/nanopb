/*
 * demo_filter_udp/_tcp from --protocol-filter=demo: the packet is a
 * google.protobuf.Any, its type_url selects the message, and every Any inside
 * is resolved the same way up to PB_VALIDATE_FILTER_MAX_ANY_DEPTH (4).
 */

#include <stdio.h>
#include <string.h>

#include <pb_encode.h>
#include "protocol.pb.h"
#include "demo_filter.h"

static int failures = 0;

#define EXPECT(cond, msg) do { \
    printf("    [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) failures++; \
} while (0)

/* Wrap an encoded message into an Any with the given type_url. */
static void pack(google_protobuf_Any *any, const char *url, const pb_msgdesc_t *fields, const void *msg)
{
    pb_ostream_t stream;
    memset(any, 0, sizeof(*any));
    strcpy(any->type_url, url);
    stream = pb_ostream_from_buffer(any->value.bytes, sizeof(any->value.bytes));
    if (!pb_encode(&stream, fields, msg))
        printf("encode failed: %s\n", PB_GET_ERROR(&stream));
    any->value.size = (pb_size_t)stream.bytes_written;
}

/* Encode the Any itself: that is the packet. */
static size_t packet_of(const google_protobuf_Any *any, pb_byte_t *packet, size_t size)
{
    pb_ostream_t stream = pb_ostream_from_buffer(packet, size);
    if (!pb_encode(&stream, google_protobuf_Any_fields, any))
        printf("encode failed: %s\n", PB_GET_ERROR(&stream));
    return stream.bytes_written;
}

static int filter(const google_protobuf_Any *any)
{
    static pb_byte_t packet[512];
    return demo_filter_udp(NULL, packet, packet_of(any, packet, sizeof(packet)));
}

static google_protobuf_Any ping_any(uint32_t seq)
{
    google_protobuf_Any any;
    Ping ping = Ping_init_zero;
    ping.seq = seq;
    pack(&any, "type.googleapis.com/Ping", Ping_fields, &ping);
    return any;
}

/* `levels` Batches nested inside each other around one Ping. */
static google_protobuf_Any batches(int levels)
{
    google_protobuf_Any any = ping_any(1);
    while (levels-- > 0)
    {
        Batch batch = Batch_init_zero;
        batch.items_count = 1;
        batch.items[0] = any;
        pack(&any, "type.googleapis.com/Batch", Batch_fields, &batch);
    }
    return any;
}

int main(void)
{
    static pb_byte_t packet[512];
    static const pb_byte_t garbage[] = { 0x0a, 0xff };
    google_protobuf_Any any;
    Login login = Login_init_zero;
    Envelope env = Envelope_init_zero;
    Batch batch = Batch_init_zero;

    any = ping_any(1);
    EXPECT(filter(&any) == 0, "valid Ping selected by its type_url");
    any = ping_any(0);
    EXPECT(filter(&any) == -1, "invalid Ping rejected");

    strcpy(login.user, "bob");
    pack(&any, "type.googleapis.com/Login", Login_fields, &login);
    EXPECT(filter(&any) == 0, "valid Login");
    pack(&any, "example.com/Login", Login_fields, &login);
    EXPECT(filter(&any) == 0, "any type_url host prefix is accepted");
    pack(&any, "type.googleapis.com/Unknown", Login_fields, &login);
    EXPECT(filter(&any) == -1, "type_url that is not a message of the protocol rejected");

    env.version = 1;
    env.which_body = Envelope_wrapped_tag;
    env.body.wrapped = ping_any(5);
    pack(&any, "type.googleapis.com/Envelope", Envelope_fields, &env);
    EXPECT(filter(&any) == 0, "Any in a oneof arm resolved");
    env.body.wrapped = ping_any(0);
    pack(&any, "type.googleapis.com/Envelope", Envelope_fields, &env);
    EXPECT(filter(&any) == -1, "invalid message inside the oneof Any rejected");
    env.which_body = Envelope_ping_tag;
    env.body.ping.seq = 3;
    pack(&any, "type.googleapis.com/Envelope", Envelope_fields, &env);
    EXPECT(filter(&any) == 0, "oneof arm without Any is just validated");
    env.which_body = 0;
    pack(&any, "type.googleapis.com/Envelope", Envelope_fields, &env);
    EXPECT(filter(&any) == 0, "unset oneof is fine");

    batch.items_count = 2;
    batch.items[0] = ping_any(1);
    strcpy(login.user, "al");
    pack(&batch.items[1], "type.googleapis.com/Login", Login_fields, &login);
    pack(&any, "type.googleapis.com/Batch", Batch_fields, &batch);
    EXPECT(filter(&any) == -1, "invalid second item of a repeated Any rejected");
    strcpy(login.user, "alice");
    pack(&batch.items[1], "type.googleapis.com/Login", Login_fields, &login);
    pack(&any, "type.googleapis.com/Batch", Batch_fields, &batch);
    EXPECT(filter(&any) == 0, "every item of a repeated Any resolved");

    any = batches(3);
    EXPECT(filter(&any) == 0, "Any nested 4 levels (3 Batches + Ping) accepted");
    any = batches(4);
    EXPECT(filter(&any) == -1, "Any nested deeper than PB_VALIDATE_FILTER_MAX_ANY_DEPTH rejected");

    EXPECT(demo_filter_udp(NULL, garbage, sizeof(garbage)) == -1, "packet that is not an Any rejected");
    any = ping_any(2);
    EXPECT(demo_filter_tcp(NULL, packet, packet_of(&any, packet, sizeof(packet)), true) == 0, "tcp wrapper");

    printf("%s\n", failures ? "FAILED" : "ALL PASSED");
    return failures ? 1 : 0;
}
