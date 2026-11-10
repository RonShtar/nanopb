/*
 * Test suite for google.protobuf.Timestamp validation
 *
 * This test exercises the timestamp validation rules (gt_now, lt_now, within)
 * to validate messages containing google.protobuf.Timestamp fields.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_validate.h"

/* Include generated headers */
#include "filter_timestamp.pb.h"
#include "filter_timestamp_validate.h"

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

/*
 * Test gt_now validation (timestamp must be after current time)
 */
static void test_gt_now_validation(void) {
    printf("\n=== Testing gt_now Validation ===\n");
    pb_violations_t viol;
    bool ok;
    
    /* Test 1: Future timestamp (should be valid) */
    TEST("Future timestamp with gt_now");
    {
        FilterTimestampFuture msg = FilterTimestampFuture_init_zero;
        msg.has_expiration = true;
        msg.expiration.seconds = time(NULL) + 3600;  /* 1 hour in the future */
        msg.expiration.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampFuture(&msg, &viol);
        EXPECT_VALID(ok, "future timestamp");
    }
    
    /* Test 2: Past timestamp (should be invalid) */
    TEST("Past timestamp with gt_now");
    {
        FilterTimestampFuture msg = FilterTimestampFuture_init_zero;
        msg.has_expiration = true;
        msg.expiration.seconds = time(NULL) - 3600;  /* 1 hour in the past */
        msg.expiration.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampFuture(&msg, &viol);
        EXPECT_INVALID(ok, "past timestamp");
    }
    
    /* Test 3: Current time (should be invalid - must be strictly greater) */
    TEST("Current time with gt_now");
    {
        FilterTimestampFuture msg = FilterTimestampFuture_init_zero;
        msg.has_expiration = true;
        msg.expiration.seconds = time(NULL);  /* Current time */
        msg.expiration.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampFuture(&msg, &viol);
        EXPECT_INVALID(ok, "current time");
    }
}

/*
 * Test lt_now validation (timestamp must be before current time)
 */
static void test_lt_now_validation(void) {
    printf("\n=== Testing lt_now Validation ===\n");
    pb_violations_t viol;
    bool ok;
    
    /* Test 1: Past timestamp (should be valid) */
    TEST("Past timestamp with lt_now");
    {
        FilterTimestampPast msg = FilterTimestampPast_init_zero;
        msg.has_created_at = true;
        msg.created_at.seconds = time(NULL) - 3600;  /* 1 hour in the past */
        msg.created_at.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampPast(&msg, &viol);
        EXPECT_VALID(ok, "past timestamp");
    }
    
    /* Test 2: Future timestamp (should be invalid) */
    TEST("Future timestamp with lt_now");
    {
        FilterTimestampPast msg = FilterTimestampPast_init_zero;
        msg.has_created_at = true;
        msg.created_at.seconds = time(NULL) + 3600;  /* 1 hour in the future */
        msg.created_at.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampPast(&msg, &viol);
        EXPECT_INVALID(ok, "future timestamp");
    }
    
    /* Test 3: Current time (should be invalid - must be strictly less) */
    TEST("Current time with lt_now");
    {
        FilterTimestampPast msg = FilterTimestampPast_init_zero;
        msg.has_created_at = true;
        msg.created_at.seconds = time(NULL);  /* Current time */
        msg.created_at.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampPast(&msg, &viol);
        EXPECT_INVALID(ok, "current time");
    }
}

/*
 * Test within validation (timestamp must be within N seconds from now)
 */
static void test_within_validation(void) {
    printf("\n=== Testing within Validation ===\n");
    pb_violations_t viol;
    bool ok;
    
    /* Test 1: Timestamp within range (past) */
    TEST("Timestamp within 300 seconds (past)");
    {
        FilterTimestampRecent msg = FilterTimestampRecent_init_zero;
        msg.has_event_time = true;
        msg.event_time.seconds = time(NULL) - 100;  /* 100 seconds in the past */
        msg.event_time.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampRecent(&msg, &viol);
        EXPECT_VALID(ok, "timestamp within range (past)");
    }
    
    /* Test 2: Timestamp within range (future) */
    TEST("Timestamp within 300 seconds (future)");
    {
        FilterTimestampRecent msg = FilterTimestampRecent_init_zero;
        msg.has_event_time = true;
        msg.event_time.seconds = time(NULL) + 100;  /* 100 seconds in the future */
        msg.event_time.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampRecent(&msg, &viol);
        EXPECT_VALID(ok, "timestamp within range (future)");
    }
    
    /* Test 3: Timestamp outside range (too far in past) */
    TEST("Timestamp outside 300 seconds (too far past)");
    {
        FilterTimestampRecent msg = FilterTimestampRecent_init_zero;
        msg.has_event_time = true;
        msg.event_time.seconds = time(NULL) - 400;  /* 400 seconds in the past */
        msg.event_time.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampRecent(&msg, &viol);
        EXPECT_INVALID(ok, "timestamp too far in past");
    }
    
    /* Test 4: Timestamp outside range (too far in future) */
    TEST("Timestamp outside 300 seconds (too far future)");
    {
        FilterTimestampRecent msg = FilterTimestampRecent_init_zero;
        msg.has_event_time = true;
        msg.event_time.seconds = time(NULL) + 400;  /* 400 seconds in the future */
        msg.event_time.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampRecent(&msg, &viol);
        EXPECT_INVALID(ok, "timestamp too far in future");
    }
}

/*
 * Test multiple timestamp fields in one message
 */
static void test_multiple_timestamps(void) {
    printf("\n=== Testing Multiple Timestamp Fields ===\n");
    pb_violations_t viol;
    bool ok;
    
    /* Test 1: All valid timestamps */
    TEST("All timestamps valid");
    {
        FilterTimestampMultiple msg = FilterTimestampMultiple_init_zero;
        
        msg.has_future_time = true;
        msg.future_time.seconds = time(NULL) + 3600;  /* Future */
        msg.future_time.nanos = 0;
        
        msg.has_past_time = true;
        msg.past_time.seconds = time(NULL) - 3600;  /* Past */
        msg.past_time.nanos = 0;
        
        msg.has_recent_time = true;
        msg.recent_time.seconds = time(NULL) - 30;  /* Within 60 seconds */
        msg.recent_time.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampMultiple(&msg, &viol);
        EXPECT_VALID(ok, "all timestamps valid");
    }
    
    /* Test 2: Invalid future timestamp */
    TEST("Invalid future timestamp");
    {
        FilterTimestampMultiple msg = FilterTimestampMultiple_init_zero;
        
        msg.has_future_time = true;
        msg.future_time.seconds = time(NULL) - 100;  /* Past (invalid for gt_now) */
        msg.future_time.nanos = 0;
        
        msg.has_past_time = true;
        msg.past_time.seconds = time(NULL) - 3600;  /* Past */
        msg.past_time.nanos = 0;
        
        msg.has_recent_time = true;
        msg.recent_time.seconds = time(NULL) - 30;  /* Within 60 seconds */
        msg.recent_time.nanos = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_FilterTimestampMultiple(&msg, &viol);
        EXPECT_INVALID(ok, "invalid future timestamp");
    }
}

int main(void) {
    printf("Filter Timestamp Validation Tests\n");
    printf("==================================\n");
    
    test_gt_now_validation();
    test_lt_now_validation();
    test_within_validation();
    test_multiple_timestamps();
    
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
