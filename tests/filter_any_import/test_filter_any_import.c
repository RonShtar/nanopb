/* Gateway_filter_udp with an Any payload type from another .proto: links only
 * if the payload's validator is defined once, in payload_validate.c. */

#include <stdio.h>
#include <string.h>

#include <pb_encode.h>
#include "gateway.pb.h"
#include "payload.pb.h"

static int run(int32_t value)
{
    static pb_byte_t packet[256];
    Gateway gateway = Gateway_init_zero;
    Reading reading = Reading_init_zero;
    pb_ostream_t stream;

    reading.value = value;
    gateway.has_body = true;
    strcpy(gateway.body.type_url, "type.googleapis.com/Reading");
    stream = pb_ostream_from_buffer(gateway.body.value.bytes, sizeof(gateway.body.value.bytes));
    pb_encode(&stream, Reading_fields, &reading);
    gateway.body.value.size = (pb_size_t)stream.bytes_written;

    stream = pb_ostream_from_buffer(packet, sizeof(packet));
    pb_encode(&stream, Gateway_fields, &gateway);
    return Gateway_filter_udp(NULL, packet, stream.bytes_written);
}

int main(void)
{
    int failures = 0;
    if (run(50) != 0) { printf("FAIL valid payload rejected\n"); failures++; }
    if (run(500) != -1) { printf("FAIL invalid payload accepted\n"); failures++; }
    printf("%s\n", failures ? "FAILED" : "ALL PASSED");
    return failures ? 1 : 0;
}
