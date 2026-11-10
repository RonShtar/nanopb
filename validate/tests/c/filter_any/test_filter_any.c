/*
 * Test suite for google.protobuf.Any envelope pattern validation
 *
 * This test exercises the FilterAnyAllowed_filter_tcp/FilterAnyAllowed_filter_udp functions generated with --envelope-mode=any
 * to validate messages containing google.protobuf.Any fields with type restrictions.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_validate.h"

/* Include generated headers */
#include "filter_any.pb.h"
#include "filter_any_validate.h"
#include "google/protobuf/any.pb.h"

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

/* Helper function to pack a message into an Any field */
static bool pack_any(google_protobuf_Any *any, const char *type_url, 
                     const pb_msgdesc_t *fields, const void *src_struct) {
    /* Set the type_url */
    strncpy(any->type_url, type_url, sizeof(any->type_url) - 1);
    any->type_url[sizeof(any->type_url) - 1] = '\0';
    
    /* Encode the message into the value field */
    pb_ostream_t stream = pb_ostream_from_buffer(any->value.bytes, sizeof(any->value.bytes));
    bool status = pb_encode(&stream, fields, src_struct);
    if (status) {
        any->value.size = stream.bytes_written;
    }
    return status;
}

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
 * Test valid messages with allowed Any types using FilterAnyAllowed_filter_udp
 */
static void test_valid_allowed_any(void) {
    printf("\n=== Testing Valid Allowed Any Messages with FilterAnyAllowed_filter_udp ===\n");
    uint8_t buffer[512];
    size_t msg_len;
    int result;
    
    /* Test 1: Valid UserInfo in allowed Any */
    TEST("Valid UserInfo in allowed Any field");
    {
        UserInfo user = UserInfo_init_zero;
        user.user_id = 123;  /* > 0: valid */
        strcpy(user.email, "user@example.com");  /* valid email */
        user.age = 25;  /* 0-150: valid */
        
        FilterAnyAllowed msg = FilterAnyAllowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/UserInfo", &UserInfo_msg, &user));
        
        /* Encode to buffer */
        assert(encode_message(&FilterAnyAllowed_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterAnyAllowed_filter_udp */
        result = FilterAnyAllowed_filter_udp(NULL, buffer, msg_len);
        EXPECT_VALID(result == 0, "valid UserInfo in allowed Any");
    }
    
    /* Test 2: Valid ProductInfo in allowed Any */
    TEST("Valid ProductInfo in allowed Any field");
    {
        ProductInfo product = ProductInfo_init_zero;
        product.product_id = 456;  /* > 0: valid */
        strcpy(product.name, "Widget");  /* min_len 1: valid */
        product.price = 19.99;  /* >= 0.0: valid */
        
        FilterAnyAllowed msg = FilterAnyAllowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/ProductInfo", &ProductInfo_msg, &product));
        
        /* Encode to buffer */
        assert(encode_message(&FilterAnyAllowed_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterAnyAllowed_filter_udp */
        result = FilterAnyAllowed_filter_udp(NULL, buffer, msg_len);
        EXPECT_VALID(result == 0, "valid ProductInfo in allowed Any");
    }
}

/*
 * Test invalid messages with disallowed Any types using FilterAnyAllowed_filter_udp
 */
static void test_invalid_allowed_any(void) {
    printf("\n=== Testing Invalid Allowed Any Messages with FilterAnyAllowed_filter_udp ===\n");
    uint8_t buffer[512];
    size_t msg_len;
    int result;
    
    /* Test 1: OrderInfo not allowed in FilterAnyAllowed */
    TEST("OrderInfo not in allowed types");
    {
        OrderInfo order = OrderInfo_init_zero;
        order.order_id = 789;
        order.total = 99.99;
        
        FilterAnyAllowed msg = FilterAnyAllowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/OrderInfo", &OrderInfo_msg, &order));
        
        /* Encode to buffer */
        assert(encode_message(&FilterAnyAllowed_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterAnyAllowed_filter_udp - should reject due to any.in rules */
        result = FilterAnyAllowed_filter_udp(NULL, buffer, msg_len);
        EXPECT_INVALID(result == 0, "OrderInfo not in allowed types");
    }
    
    /* Test 2: Invalid UserInfo payload (negative user_id) */
    TEST("Invalid UserInfo payload in allowed Any");
    {
        UserInfo user = UserInfo_init_zero;
        user.user_id = -1;  /* <= 0: invalid */
        strcpy(user.email, "user@example.com");
        user.age = 25;
        
        FilterAnyAllowed msg = FilterAnyAllowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/UserInfo", &UserInfo_msg, &user));
        
        /* Encode to buffer */
        assert(encode_message(&FilterAnyAllowed_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterAnyAllowed_filter_udp - should reject */
        result = FilterAnyAllowed_filter_udp(NULL, buffer, msg_len);
        EXPECT_INVALID(result == 0, "invalid UserInfo payload");
    }
    
    /* Test 3: Invalid email in UserInfo */
    TEST("Invalid email format in UserInfo");
    {
        UserInfo user = UserInfo_init_zero;
        user.user_id = 123;
        strcpy(user.email, "not-an-email");  /* invalid email format */
        user.age = 25;
        
        FilterAnyAllowed msg = FilterAnyAllowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/UserInfo", &UserInfo_msg, &user));
        
        /* Encode to buffer */
        assert(encode_message(&FilterAnyAllowed_msg, &msg, buffer, sizeof(buffer), &msg_len));
        
        /* Test with FilterAnyAllowed_filter_udp - should reject */
        result = FilterAnyAllowed_filter_udp(NULL, buffer, msg_len);
        EXPECT_INVALID(result == 0, "invalid email format");
    }
}

/*
 * Test the any.not_in deny-list on FilterAnyDisallowed.
 *
 * FilterAnyDisallowed is deliberately NOT a filter entrypoint: a deny-list says
 * what is forbidden, not what is decodable, so it cannot produce a dispatch
 * table and the generator refuses to build a filter from one. The rule is still
 * enforced by the generated validator, which is what this exercises.
 */
static void test_disallowed_any(void) {
    printf("\n=== Testing any.not_in deny-list via pb_validate_FilterAnyDisallowed ===\n");
    pb_violations_t violations;
    bool valid;

    /* Test 1: UserInfo is not on the deny-list, so it passes */
    TEST("UserInfo accepted by any.not_in deny-list");
    {
        UserInfo user = UserInfo_init_zero;
        user.user_id = 123;
        strcpy(user.email, "user@example.com");
        user.age = 25;

        FilterAnyDisallowed msg = FilterAnyDisallowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/UserInfo", &UserInfo_msg, &user));

        pb_violations_init(&violations);
        valid = pb_validate_FilterAnyDisallowed(&msg, &violations);
        EXPECT_VALID(valid, "UserInfo not on the deny-list");
    }

    /* Test 2: OrderInfo is explicitly denied */
    TEST("OrderInfo rejected by any.not_in deny-list");
    {
        OrderInfo order = OrderInfo_init_zero;
        order.order_id = 789;
        order.total = 99.99;

        FilterAnyDisallowed msg = FilterAnyDisallowed_init_zero;
        msg.has_payload = true;
        assert(pack_any(&msg.payload, "type.googleapis.com/OrderInfo", &OrderInfo_msg, &order));

        pb_violations_init(&violations);
        valid = pb_validate_FilterAnyDisallowed(&msg, &violations);
        EXPECT_INVALID(valid, "OrderInfo explicitly disallowed");
    }
}

int main(void) {
    printf("Filter Any Validation Tests\n");
    printf("============================\n");
    
    test_valid_allowed_any();
    test_invalid_allowed_any();
    test_disallowed_any();
    
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
