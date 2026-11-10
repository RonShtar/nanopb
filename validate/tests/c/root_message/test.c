/*
 * Test suite for --root-message functionality
 * 
 * Tests the single-root-message mode where rootmsg_TestPacket_filter_tcp/rootmsg_TestPacket_filter_udp
 * decode and validate a specific message type directly without
 * envelope/Any detection.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_validate.h"

/* Include generated headers */
#include "root_message.pb.h"
#include "root_message_validate.h"

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* Helper macros */
#define TEST(name) do { \
    printf("  Testing: %s\n", name); \
} while(0)

#define EXPECT_PASS(result, msg) do { \
    if (result == 0) { \
        tests_passed++; \
        printf("    [PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] Expected pass, got failure: %s\n", msg); \
    } \
} while(0)

#define EXPECT_FAIL(result, msg) do { \
    if (result != 0) { \
        tests_passed++; \
        printf("    [PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] Expected failure, got pass: %s\n", msg); \
    } \
} while(0)

/* Helper to encode a TestPacket message */
static bool encode_test_packet(uint8_t *buffer, size_t *size, 
                               const char *name, int32_t value,
                               const char *nested_desc, int32_t nested_count,
                               bool include_nested)
{
    rootmsg_TestPacket msg = rootmsg_TestPacket_init_zero;
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, *size);
    
    /* Set required fields */
    if (name) {
        strncpy(msg.name, name, sizeof(msg.name) - 1);
        msg.name[sizeof(msg.name) - 1] = '\0';
    }
    msg.value = value;
    
    /* Set nested message if included */
    if (include_nested) {
        msg.has_nested = true;
        if (nested_desc) {
            strncpy(msg.nested.description, nested_desc, sizeof(msg.nested.description) - 1);
            msg.nested.description[sizeof(msg.nested.description) - 1] = '\0';
        }
        msg.nested.count = nested_count;
    }
    
    if (!pb_encode(&stream, &rootmsg_TestPacket_msg, &msg)) {
        printf("    Encode error: %s\n", PB_GET_ERROR(&stream));
        return false;
    }
    
    *size = stream.bytes_written;
    return true;
}

/* Test 1: Valid message through rootmsg_TestPacket_filter_udp */
static void test_valid_message_udp(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Valid message - rootmsg_TestPacket_filter_udp");
    
    /* Create a valid TestPacket: name is non-empty, value > 0 */
    if (!encode_test_packet(buffer, &size, "test_name", 42, NULL, 0, false)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_udp(NULL, buffer, size);
    EXPECT_PASS(result, "Valid message should pass validation");
}

/* Test 2: Valid message through rootmsg_TestPacket_filter_tcp */
static void test_valid_message_tcp(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Valid message - rootmsg_TestPacket_filter_tcp");
    
    /* Create a valid TestPacket */
    if (!encode_test_packet(buffer, &size, "hello", 100, NULL, 0, false)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_tcp(NULL, buffer, size, true);
    EXPECT_PASS(result, "Valid message should pass validation");
    
    /* Test with is_to_server = false */
    result = rootmsg_TestPacket_filter_tcp(NULL, buffer, size, false);
    EXPECT_PASS(result, "Valid message should pass with is_to_server=false");
}

/* Test 3: Invalid message - empty name (violates min_len = 1) */
static void test_invalid_name_empty(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Invalid message - empty name");
    
    /* Create an invalid TestPacket: name is empty, violates min_len=1 */
    if (!encode_test_packet(buffer, &size, "", 42, NULL, 0, false)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_udp(NULL, buffer, size);
    EXPECT_FAIL(result, "Empty name should fail validation");
}

/* Test 4: Invalid message - value not > 0 */
static void test_invalid_value_zero(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Invalid message - value is 0");
    
    /* Create an invalid TestPacket: value is 0, violates gt=0 */
    if (!encode_test_packet(buffer, &size, "test", 0, NULL, 0, false)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_udp(NULL, buffer, size);
    EXPECT_FAIL(result, "Value of 0 should fail validation");
}

/* Test 5: Invalid message - negative value */
static void test_invalid_value_negative(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Invalid message - negative value");
    
    /* Create an invalid TestPacket: value is negative, violates gt=0 */
    if (!encode_test_packet(buffer, &size, "test", -5, NULL, 0, false)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_udp(NULL, buffer, size);
    EXPECT_FAIL(result, "Negative value should fail validation");
}

/* Test 6: Valid message with nested data */
static void test_valid_nested_message(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Valid message with nested data");
    
    /* Create a valid TestPacket with nested data */
    if (!encode_test_packet(buffer, &size, "parent", 10, "child desc", 5, true)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_udp(NULL, buffer, size);
    EXPECT_PASS(result, "Valid nested message should pass validation");
}

/* Test 7: Invalid nested data - negative count */
static void test_invalid_nested_count(void)
{
    uint8_t buffer[256];
    size_t size = sizeof(buffer);
    int result;
    
    TEST("Invalid nested data - negative count");
    
    /* Create a TestPacket with invalid nested data (count < 0, violates gte=0) */
    if (!encode_test_packet(buffer, &size, "parent", 10, "desc", -1, true)) {
        tests_failed++;
        printf("    [FAIL] Could not encode test message\n");
        return;
    }
    
    result = rootmsg_TestPacket_filter_udp(NULL, buffer, size);
    EXPECT_FAIL(result, "Nested negative count should fail validation");
}

/* Test 8: Decode failure - malformed data */
static void test_decode_failure(void)
{
    uint8_t garbage[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int result;
    
    TEST("Decode failure - malformed data");
    
    result = rootmsg_TestPacket_filter_udp(NULL, garbage, sizeof(garbage));
    EXPECT_FAIL(result, "Malformed data should fail decoding");
    
    result = rootmsg_TestPacket_filter_tcp(NULL, garbage, sizeof(garbage), true);
    EXPECT_FAIL(result, "Malformed data should fail on TCP too");
}

/* Test 9: Zero-length buffer */
static void test_empty_buffer(void)
{
    /* A placeholder buffer - we pass size 0 so contents don't matter */
    uint8_t placeholder[1] = {0};
    int result;
    
    TEST("Zero-length buffer");
    
    /* A zero-length protobuf message will decode to default values,
       but validation should fail because name is empty (min_len=1) 
       and value is 0 (gt=0) */
    result = rootmsg_TestPacket_filter_udp(NULL, placeholder, 0);
    /* An empty buffer will decode to default values (empty string, 0), 
       which should fail validation */
    EXPECT_FAIL(result, "Empty buffer should fail validation");
}

int main(void)
{
    printf("=== Root Message Mode Test Suite ===\n\n");
    
    printf("Testing rootmsg_TestPacket_filter_udp and rootmsg_TestPacket_filter_tcp in single-root-message mode:\n\n");
    
    /* Run all tests */
    test_valid_message_udp();
    test_valid_message_tcp();
    test_invalid_name_empty();
    test_invalid_value_zero();
    test_invalid_value_negative();
    test_valid_nested_message();
    test_invalid_nested_count();
    test_decode_failure();
    test_empty_buffer();
    
    printf("\n=== Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        printf("\nSOME TESTS FAILED!\n");
        return 1;
    } else {
        printf("\nAll tests passed!\n");
        return 0;
    }
}
