/*
 * Test suite for oneof envelope pattern validation
 *
 * This test exercises validation of messages with --envelope-mode=oneof
 * using the opcode + oneof pattern. The generated FilterOneofMessage_filter_tcp/FilterOneofMessage_filter_udp functions
 * are declared in the header but have known issues in the current generator.
 * 
 * This test validates the core validation functionality for oneof patterns.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_validate.h"

/* Include generated headers */
#include "filter_oneof.pb.h"
#include "filter_oneof_validate.h"

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* Helper macros */
#define TEST(name) do { \
    printf("  Testing: %s\n", name); \
} while(0)

#define EXPECT_VALID(result, msg) do { \
    if (result) { \
        tests_passed++; \
        printf("    [PASS] Valid message accepted: %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] Expected valid, got invalid: %s\n", msg); \
    } \
} while(0)

#define EXPECT_INVALID(result, msg) do { \
    if (!(result)) { \
        tests_passed++; \
        printf("    [PASS] Invalid message rejected: %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] Expected invalid, got valid: %s\n", msg); \
    } \
} while(0)

/* Helper function to encode a message to a buffer */
static bool encode_message(const pb_msgdesc_t *fields, const void *src_struct, 
                          uint8_t *buffer, size_t buffer_size, size_t *msg_len) {
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, buffer_size);
    bool status = pb_encode(&stream, fields, src_struct);
    if (status) {
        *msg_len = stream.bytes_written;
    }
    return status;
}

/*
 * Test valid messages with different oneof variants using FilterOneofMessage_filter_udp/FilterOneofMessage_filter_tcp
 */
static void test_valid_messages(void) {
    printf("\n=== Testing Valid Messages with FilterOneofMessage_filter_udp ===\n");
    uint8_t buffer[256];
    size_t msg_len;
    int result;
    
    /* Test 1: Valid auth message */
    TEST("Valid auth message with username >= 3 chars");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_auth_username_tag;
        strcpy(msg.payload.auth_username, "alice");
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_udp */
        result = FilterOneofMessage_filter_udp(NULL, buffer, msg_len);
        EXPECT_VALID(result == 0, "auth message with valid username");
    }
    
    /* Test 2: Valid data message */
    TEST("Valid data message with non-negative value");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_data_value_tag;
        msg.payload.data_value = 42;
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_udp */
        result = FilterOneofMessage_filter_udp(NULL, buffer, msg_len);
        EXPECT_VALID(result == 0, "data message with valid value");
    }
    
    /* Test 3: Valid status message */
    TEST("Valid status message with nested validation");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_status_tag;
        msg.payload.status.status_code = 200;
        strcpy(msg.payload.status.status_message, "OK");
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_udp */
        result = FilterOneofMessage_filter_udp(NULL, buffer, msg_len);
        EXPECT_VALID(result == 0, "status message with valid nested payload");
    }
    
    printf("\n=== Testing Valid Messages with FilterOneofMessage_filter_tcp ===\n");
    
    /* Test 4: Valid message with FilterOneofMessage_filter_tcp (client to server) */
    TEST("Valid auth message via FilterOneofMessage_filter_tcp (client->server)");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_auth_username_tag;
        strcpy(msg.payload.auth_username, "bob");
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_tcp (is_to_server = true) */
        result = FilterOneofMessage_filter_tcp(NULL, buffer, msg_len, true);
        EXPECT_VALID(result == 0, "auth via FilterOneofMessage_filter_tcp to server");
    }
    
    /* Test 5: Valid message with FilterOneofMessage_filter_tcp (server to client) */
    TEST("Valid data message via FilterOneofMessage_filter_tcp (server->client)");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_data_value_tag;
        msg.payload.data_value = 100;
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_tcp (is_to_server = false) */
        result = FilterOneofMessage_filter_tcp(NULL, buffer, msg_len, false);
        EXPECT_VALID(result == 0, "data via FilterOneofMessage_filter_tcp from server");
    }
}

/*
 * Test invalid messages with validation rule violations using filter functions
 */
static void test_invalid_messages(void) {
    printf("\n=== Testing Invalid Messages with FilterOneofMessage_filter_udp ===\n");
    uint8_t buffer[256];
    size_t msg_len;
    int result;
    
    /* Test 1: Invalid auth username (too short) */
    TEST("Invalid auth username (< 3 chars)");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_auth_username_tag;
        strcpy(msg.payload.auth_username, "ab");  /* Invalid: min_len is 3 */
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_udp - should reject */
        result = FilterOneofMessage_filter_udp(NULL, buffer, msg_len);
        EXPECT_INVALID(result == 0, "username too short");
    }
    
    /* Test 2: Invalid data value (negative) */
    TEST("Invalid data value (negative)");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_data_value_tag;
        msg.payload.data_value = -1;  /* Invalid: must be >= 0 */
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_udp - should reject */
        result = FilterOneofMessage_filter_udp(NULL, buffer, msg_len);
        EXPECT_INVALID(result == 0, "negative data value");
    }
    
    printf("\n=== Testing Invalid Messages with FilterOneofMessage_filter_tcp ===\n");
    
    /* Test 3: Invalid via FilterOneofMessage_filter_tcp */
    TEST("Invalid auth username via FilterOneofMessage_filter_tcp");
    {
        FilterOneofMessage msg = FilterOneofMessage_init_zero;
        msg.which_payload = FilterOneofMessage_auth_username_tag;
        strcpy(msg.payload.auth_username, "x");  /* Too short */
        
        /* Encode to buffer */
        assert(encode_message(&FilterOneofMessage_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterOneofMessage_filter_tcp - should reject */
        result = FilterOneofMessage_filter_tcp(NULL, buffer, msg_len, true);
        EXPECT_INVALID(result == 0, "invalid via FilterOneofMessage_filter_tcp");
    }
}

int main(void) {
    printf("Filter Oneof Validation Tests\n");
    printf("==============================\n");
    
    test_valid_messages();
    test_invalid_messages();
    
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        printf("\nFAILURE: %d test(s) failed\n", tests_failed);
        return 1;
    } else {
        printf("\nSUCCESS: All tests passed\n");
        return 0;
    }
}
