/*
 * Test suite for several filter entrypoints linked into one binary:
 * Command_filter_* and Status_filter_* (both from filter_multi.proto) and
 * Report_filter_* (from filter_multi_report.proto).
 */

#include <stdio.h>
#include <string.h>

#include "pb.h"
#include "pb_encode.h"
#include "filter_multi.pb.h"
#include "filter_multi_report.pb.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define EXPECT(cond, msg) do { \
    if (cond) { \
        tests_passed++; \
        printf("    [PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] %s\n", msg); \
    } \
} while(0)

static size_t encode(const pb_msgdesc_t *fields, const void *msg, uint8_t *buffer, size_t size)
{
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, size);
    if (!pb_encode(&stream, fields, msg))
    {
        printf("    [FAIL] encode: %s\n", PB_GET_ERROR(&stream));
        tests_failed++;
        return 0;
    }
    return stream.bytes_written;
}

static void test_command(void)
{
    uint8_t buffer[64];
    size_t len;
    Command cmd = Command_init_zero;

    printf("\n=== Command (oneof dispatch) ===\n");

    cmd.which_body = Command_ping_tag;
    cmd.body.ping.seq = 5;
    len = encode(Command_fields, &cmd, buffer, sizeof(buffer));
    EXPECT(Command_filter_udp(NULL, buffer, len) == 0, "ping seq=5 allowed (udp)");
    EXPECT(Command_filter_tcp(NULL, buffer, len, true) == 0, "ping seq=5 allowed (tcp)");

    cmd.body.ping.seq = 0;
    len = encode(Command_fields, &cmd, buffer, sizeof(buffer));
    EXPECT(Command_filter_udp(NULL, buffer, len) == -1, "ping seq=0 rejected");

    memset(&cmd, 0, sizeof(cmd));
    cmd.which_body = Command_login_tag;
    strcpy(cmd.body.login.user, "bob");
    len = encode(Command_fields, &cmd, buffer, sizeof(buffer));
    EXPECT(Command_filter_udp(NULL, buffer, len) == 0, "login bob allowed");

    strcpy(cmd.body.login.user, "al");
    len = encode(Command_fields, &cmd, buffer, sizeof(buffer));
    EXPECT(Command_filter_udp(NULL, buffer, len) == -1, "login al rejected");

    memset(&cmd, 0, sizeof(cmd));
    len = encode(Command_fields, &cmd, buffer, sizeof(buffer));
    EXPECT(Command_filter_udp(NULL, buffer, len) == -1, "empty oneof rejected");
}

static void test_status(void)
{
    uint8_t buffer[16];
    size_t len;
    Status status = Status_init_zero;
    const uint8_t garbage[] = { 0x08 };

    printf("\n=== Status (single message) ===\n");

    status.code = 42;
    len = encode(Status_fields, &status, buffer, sizeof(buffer));
    EXPECT(Status_filter_udp(NULL, buffer, len) == 0, "code=42 allowed");

    status.code = 100;
    len = encode(Status_fields, &status, buffer, sizeof(buffer));
    EXPECT(Status_filter_tcp(NULL, buffer, len, false) == -1, "code=100 rejected");

    EXPECT(Status_filter_udp(NULL, garbage, sizeof(garbage)) == -1, "truncated packet rejected");
}

static void test_report(void)
{
    uint8_t buffer[32];
    size_t len;
    Report report = Report_init_zero;

    printf("\n=== Report (filter from another file) ===\n");

    report.has_last = true;
    report.last.seq = 1;
    report.count = 10;
    len = encode(Report_fields, &report, buffer, sizeof(buffer));
    EXPECT(Report_filter_udp(NULL, buffer, len) == 0, "count=10 allowed");

    report.count = 11;
    len = encode(Report_fields, &report, buffer, sizeof(buffer));
    EXPECT(Report_filter_udp(NULL, buffer, len) == -1, "count=11 rejected");

    report.count = 1;
    report.last.seq = 0;
    len = encode(Report_fields, &report, buffer, sizeof(buffer));
    EXPECT(Report_filter_udp(NULL, buffer, len) == -1, "nested last.seq=0 rejected");
}

int main(void)
{
    test_command();
    test_status();
    test_report();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
