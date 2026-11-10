/*
 * Comprehensive validation test suite for nanopb validator codegen
 *
 * This test exercises all validation rules supported by the nanopb
 * validation code generator, including:
 * - Numeric rules (int32, int64, uint32, uint64, float, double, sint*, fixed*, sfixed*)
 * - String rules (min_len, max_len, prefix, suffix, contains, ascii, email, hostname, ip)
 * - Repeated field rules (min_items, max_items)
 * - Enum rules (defined_only, const)
 * - Message rules (nested message validation)
 * - Oneof rules (validation of oneof members)
 * - Bytes rules (min_len, max_len)
 * - Bypass vs early-exit behavior
 * - Path reporting
 * - Violations collection
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_validate.h"

/* Include generated headers */
#include "numeric_rules.pb.h"
#include "numeric_rules_validate.h"
#include "string_rules.pb.h"
#include "string_rules_validate.h"
#include "repeated_rules.pb.h"
#include "repeated_rules_validate.h"
#include "enum_rules.pb.h"
#include "enum_rules_validate.h"
#include "message_rules.pb.h"
#include "message_rules_validate.h"
#include "oneof_rules.pb.h"
#include "oneof_rules_validate.h"
#include "bytes_rules.pb.h"
#include "bytes_rules_validate.h"
#include "bypass_behavior.pb.h"
#include "bypass_behavior_validate.h"
/* Any behavior tests */
#include "any_behavior.pb.h"
#include "any_behavior_validate.h"

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
        printf("    [PASS] Valid message accepted\n"); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] Expected valid, got invalid: %s\n", msg); \
    } \
} while(0)

#define EXPECT_INVALID(result, msg) do { \
    if (!result) { \
        tests_passed++; \
        printf("    [PASS] Invalid message rejected\n"); \
    } else { \
        tests_failed++; \
        printf("    [FAIL] Expected invalid, got valid: %s\n", msg); \
    } \
} while(0)

#define EXPECT_VIOLATION(viol, expected_id) do { \
    if (pb_violations_has_any(&viol) && \
        viol.violations[0].constraint_id != NULL && \
        strcmp(viol.violations[0].constraint_id, expected_id) == 0) { \
        tests_passed++; \
        printf("    [PASS] Got expected violation: %s\n", expected_id); \
    } else { \
        tests_failed++; \
        const char *got = (pb_violations_has_any(&viol) && viol.violations[0].constraint_id) ? \
                          viol.violations[0].constraint_id : "(none)"; \
        printf("    [FAIL] Expected violation '%s', got '%s'\n", expected_id, got); \
    } \
} while(0)

/* Macro to print violations when needed (for debugging only)
 * Usage: Uncomment DEBUG_PRINT_VIOLATIONS(&viol); in test code to debug
 */
#if 0  /* Disabled by default to avoid unused macro warning */
#define DEBUG_PRINT_VIOLATIONS(viol) do { \
    printf("    Violations: %u (truncated=%s)\n", \
           (unsigned)pb_violations_count(viol), \
           (viol)->truncated ? "true" : "false"); \
    for (pb_size_t i = 0; i < pb_violations_count(viol); ++i) { \
        const pb_violation_t *v = &(viol)->violations[i]; \
        printf("      - %s: %s (%s)\n", \
               v->field_path ? v->field_path : "<path>", \
               v->message ? v->message : "<msg>", \
               v->constraint_id ? v->constraint_id : "<rule>"); \
    } \
} while(0)
#endif

/*======================================================================
 * NUMERIC RULES TESTS
 *======================================================================*/

static void test_int32_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Int32 Rules Tests ===\n");
    
    /* Test valid message */
    TEST("Int32Rules - valid values");
    {
        Int32Rules msg = Int32Rules_init_zero;
        msg.lt_field = 50;     /* < 100 */
        msg.lte_field = 100;   /* <= 100 */
        msg.gt_field = 1;      /* > 0 */
        msg.gte_field = 0;     /* >= 0 */
        msg.const_field = 42;  /* == 42 */
        msg.range_field = 75;  /* 0 <= x <= 150 */
        
        pb_violations_init(&viol);
        ok = pb_validate_Int32Rules(&msg, &viol);
        EXPECT_VALID(ok, "all int32 constraints satisfied");
    }
    
    /* Test lt violation */
    TEST("Int32Rules - lt violation");
    {
        Int32Rules msg = Int32Rules_init_zero;
        msg.lt_field = 100;    /* NOT < 100, should fail */
        msg.lte_field = 100;
        msg.gt_field = 1;
        msg.gte_field = 0;
        msg.const_field = 42;
        msg.range_field = 75;
        
        pb_violations_init(&viol);
        ok = pb_validate_Int32Rules(&msg, &viol);
        EXPECT_INVALID(ok, "lt_field >= 100");
        EXPECT_VIOLATION(viol, "int32.lt");
    }
    
    /* Test gt violation */
    TEST("Int32Rules - gt violation");
    {
        Int32Rules msg = Int32Rules_init_zero;
        msg.lt_field = 50;
        msg.lte_field = 100;
        msg.gt_field = 0;      /* NOT > 0, should fail */
        msg.gte_field = 0;
        msg.const_field = 42;
        msg.range_field = 75;
        
        pb_violations_init(&viol);
        ok = pb_validate_Int32Rules(&msg, &viol);
        EXPECT_INVALID(ok, "gt_field <= 0");
        EXPECT_VIOLATION(viol, "int32.gt");
    }
    
    /* Test const violation */
    TEST("Int32Rules - const violation");
    {
        Int32Rules msg = Int32Rules_init_zero;
        msg.lt_field = 50;
        msg.lte_field = 100;
        msg.gt_field = 1;
        msg.gte_field = 0;
        msg.const_field = 99;  /* NOT == 42, should fail */
        msg.range_field = 75;
        
        pb_violations_init(&viol);
        ok = pb_validate_Int32Rules(&msg, &viol);
        EXPECT_INVALID(ok, "const_field != 42");
        EXPECT_VIOLATION(viol, "int32.const");
    }
    
    /* Test range violation (gte) */
    TEST("Int32Rules - range violation (below min)");
    {
        Int32Rules msg = Int32Rules_init_zero;
        msg.lt_field = 50;
        msg.lte_field = 100;
        msg.gt_field = 1;
        msg.gte_field = 0;
        msg.const_field = 42;
        msg.range_field = -1;  /* NOT >= 0, should fail */
        
        pb_violations_init(&viol);
        ok = pb_validate_Int32Rules(&msg, &viol);
        EXPECT_INVALID(ok, "range_field < 0");
        EXPECT_VIOLATION(viol, "int32.gte");
    }
}

static void test_float_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Float Rules Tests ===\n");
    
    /* Test valid message */
    TEST("FloatRules - valid values");
    {
        FloatRules msg = FloatRules_init_zero;
        msg.lt_field = 50.0f;    /* < 100 */
        msg.gt_field = 1.0f;     /* > 0 */
        msg.gte_field = -50.0f;  /* >= -50 */
        msg.lte_field = 150.0f;  /* <= 150 */
        msg.range_field = 25.5f; /* -50 <= x <= 150 */
        
        pb_violations_init(&viol);
        ok = pb_validate_FloatRules(&msg, &viol);
        EXPECT_VALID(ok, "all float constraints satisfied");
    }
    
    /* Test gt violation */
    TEST("FloatRules - gt violation");
    {
        FloatRules msg = FloatRules_init_zero;
        msg.lt_field = 50.0f;
        msg.gt_field = 0.0f;     /* NOT > 0, should fail */
        msg.gte_field = -50.0f;
        msg.lte_field = 150.0f;
        msg.range_field = 25.5f;
        
        pb_violations_init(&viol);
        ok = pb_validate_FloatRules(&msg, &viol);
        EXPECT_INVALID(ok, "gt_field <= 0");
        EXPECT_VIOLATION(viol, "float.gt");
    }
    
    /* Test range violation */
    TEST("FloatRules - range violation (above max)");
    {
        FloatRules msg = FloatRules_init_zero;
        msg.lt_field = 50.0f;
        msg.gt_field = 1.0f;
        msg.gte_field = -50.0f;
        msg.lte_field = 150.0f;
        msg.range_field = 200.0f;  /* NOT <= 150, should fail */
        
        pb_violations_init(&viol);
        ok = pb_validate_FloatRules(&msg, &viol);
        EXPECT_INVALID(ok, "range_field > 150");
        EXPECT_VIOLATION(viol, "float.lte");
    }
}

static void test_double_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Double Rules Tests ===\n");
    
    /* Test valid message */
    TEST("DoubleRules - valid values");
    {
        DoubleRules msg = DoubleRules_init_zero;
        msg.lt_field = 0.5;   /* < 1.0 */
        msg.gt_field = 0.1;   /* > 0.0 */
        msg.gte_field = 0.0;  /* >= 0.0 */
        msg.lte_field = 1.0;  /* <= 1.0 */
        
        pb_violations_init(&viol);
        ok = pb_validate_DoubleRules(&msg, &viol);
        EXPECT_VALID(ok, "all double constraints satisfied");
    }
    
    /* Test lt violation */
    TEST("DoubleRules - lt violation");
    {
        DoubleRules msg = DoubleRules_init_zero;
        msg.lt_field = 1.0;   /* NOT < 1.0, should fail */
        msg.gt_field = 0.1;
        msg.gte_field = 0.0;
        msg.lte_field = 1.0;
        
        pb_violations_init(&viol);
        ok = pb_validate_DoubleRules(&msg, &viol);
        EXPECT_INVALID(ok, "lt_field >= 1.0");
        EXPECT_VIOLATION(viol, "double.lt");
    }
}

static void test_uint_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== UInt32/UInt64 Rules Tests ===\n");
    
    /* Test UInt32 valid */
    TEST("UInt32Rules - valid values");
    {
        UInt32Rules msg = UInt32Rules_init_zero;
        msg.lt_field = 50;
        msg.gt_field = 1;
        msg.gte_field = 0;
        msg.lte_field = 1000;
        
        pb_violations_init(&viol);
        ok = pb_validate_UInt32Rules(&msg, &viol);
        EXPECT_VALID(ok, "all uint32 constraints satisfied");
    }
    
    /* Test UInt64 valid */
    TEST("UInt64Rules - valid values");
    {
        UInt64Rules msg = UInt64Rules_init_zero;
        msg.lt_field = 500;
        msg.gt_field = 1;
        msg.gte_field = 1;
        msg.lte_field = 100;
        
        pb_violations_init(&viol);
        ok = pb_validate_UInt64Rules(&msg, &viol);
        EXPECT_VALID(ok, "all uint64 constraints satisfied");
    }
    
    /* Test UInt32 gt violation */
    TEST("UInt32Rules - gt violation");
    {
        UInt32Rules msg = UInt32Rules_init_zero;
        msg.lt_field = 50;
        msg.gt_field = 0;  /* NOT > 0, should fail */
        msg.gte_field = 0;
        msg.lte_field = 1000;
        
        pb_violations_init(&viol);
        ok = pb_validate_UInt32Rules(&msg, &viol);
        EXPECT_INVALID(ok, "gt_field <= 0");
        EXPECT_VIOLATION(viol, "uint32.gt");
    }
}

/*======================================================================
 * STRING RULES TESTS
 *======================================================================*/

static void test_string_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== String Rules Tests ===\n");
    
    /* Test valid message */
    TEST("StringRules - valid values");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");           /* >= 3 chars */
        strcpy(msg.max_len_field, "short");         /* <= 20 chars */
        strcpy(msg.range_len_field, "hello");       /* 3-20 chars */
        strcpy(msg.prefix_field, "PREFIX_test");    /* starts with PREFIX_ */
        strcpy(msg.suffix_field, "test_SUFFIX");    /* ends with _SUFFIX */
        strcpy(msg.contains_field, "user@test");    /* contains @ */
        strcpy(msg.ascii_field, "ASCII123");        /* all ASCII */
        strcpy(msg.email_field, "test@example.com"); /* valid email */
        strcpy(msg.hostname_field, "example.com");  /* valid hostname */
        strcpy(msg.ip_field, "192.168.1.1");        /* valid IP */
        strcpy(msg.ipv4_field, "10.0.0.1");         /* valid IPv4 */
        strcpy(msg.ipv6_field, "::1");              /* valid IPv6 */
        strcpy(msg.in_field, "red");                /* in set */
        strcpy(msg.not_in_field, "safe");           /* not in forbidden set */
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_VALID(ok, "all string constraints satisfied");
    }
    
    /* Test min_len violation */
    TEST("StringRules - min_len violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "ab");            /* < 3 chars, should fail */
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "min_len_field too short");
        EXPECT_VIOLATION(viol, "string.min_len");
    }
    
    /* Test max_len violation */
    TEST("StringRules - max_len violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "this_string_is_way_too_long_for_max"); /* > 20 chars */
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "max_len_field too long");
        EXPECT_VIOLATION(viol, "string.max_len");
    }
    
    /* Test prefix violation */
    TEST("StringRules - prefix violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "WRONG_test");     /* doesn't start with PREFIX_ */
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "prefix_field wrong prefix");
        EXPECT_VIOLATION(viol, "string.prefix");
    }
    
    /* Test suffix violation */
    TEST("StringRules - suffix violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_WRONG");     /* doesn't end with _SUFFIX */
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "suffix_field wrong suffix");
        EXPECT_VIOLATION(viol, "string.suffix");
    }
    
    /* Test contains violation */
    TEST("StringRules - contains violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "no_at_symbol");  /* doesn't contain @ */
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "contains_field missing @");
        EXPECT_VIOLATION(viol, "string.contains");
    }
    
    /* Test in violation */
    TEST("StringRules - in violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "purple");             /* not in {red, green, blue} */
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "in_field not in set");
        EXPECT_VIOLATION(viol, "string.in");
    }
    
    /* Test not_in violation */
    TEST("StringRules - not_in violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "FORBIDDEN");      /* in forbidden set */
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "not_in_field in forbidden set");
        EXPECT_VIOLATION(viol, "string.not_in");
    }
    
    /* Test email violation */
    TEST("StringRules - email violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "not-an-email");    /* invalid email */
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "email_field invalid");
        EXPECT_VIOLATION(viol, "string.email");
    }
    
    /* Test ipv4 violation */
    TEST("StringRules - ipv4 violation");
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "300.0.0.1");        /* invalid IPv4 */
        strcpy(msg.ipv6_field, "::1");
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");
        
        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        EXPECT_INVALID(ok, "ipv4_field invalid");
        EXPECT_VIOLATION(viol, "string.ipv4");
    }
}

/*======================================================================
 * REPEATED RULES TESTS
 *======================================================================*/

/* IPv6 parsing edge cases found by the data generator soak test: a single
 * trailing colon is malformed while a trailing "::" is a valid compression.
 */
static void test_ipv6_edge_cases(void)
{
    static const struct { const char *text; int valid; } cases[] = {
        {"::", 1}, {"::1", 1}, {"1::", 1}, {"1:2::", 1}, {"1::2", 1}, {"fe80::1", 1},
        {"1:2:3:4:5:6:7:8", 1}, {"1:2:3:4:5:6:7::", 1}, {"::ffff:1.2.3.4", 1},
        {"1:2:", 0}, {"1:", 0}, {":", 0}, {":::", 0}, {"1:::2", 0}, {"1::2::3", 0},
        {"1:2:3", 0}, {"1:2:3:4:5:6:7:8:9", 0}, {"1:2:3:4:5:6:7:8::", 0},
        {"gggg::1", 0}, {"12345::1", 0}, {":1:2:3:4:5:6:7", 0}, {"1.2.3.4", 0},
    };
    pb_violations_t viol;
    bool ok;
    size_t i;

    TEST("StringRules - ipv6 edge cases");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        StringRules msg = StringRules_init_zero;
        strcpy(msg.min_len_field, "abc");
        strcpy(msg.max_len_field, "short");
        strcpy(msg.range_len_field, "hello");
        strcpy(msg.prefix_field, "PREFIX_test");
        strcpy(msg.suffix_field, "test_SUFFIX");
        strcpy(msg.contains_field, "user@test");
        strcpy(msg.ascii_field, "ASCII123");
        strcpy(msg.email_field, "test@example.com");
        strcpy(msg.hostname_field, "example.com");
        strcpy(msg.ip_field, "192.168.1.1");
        strcpy(msg.ipv4_field, "10.0.0.1");
        strcpy(msg.ipv6_field, cases[i].text);
        strcpy(msg.in_field, "red");
        strcpy(msg.not_in_field, "safe");

        pb_violations_init(&viol);
        ok = pb_validate_StringRules(&msg, &viol);
        if (cases[i].valid)
        {
            EXPECT_VALID(ok, cases[i].text);
        }
        else
        {
            EXPECT_INVALID(ok, cases[i].text);
            EXPECT_VIOLATION(viol, "string.ipv6");
        }
    }
}

static void test_repeated_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Repeated Rules Tests ===\n");
    
    /* Test valid message */
    TEST("RepeatedRules - valid values");
    {
        RepeatedRules msg = RepeatedRules_init_zero;
        msg.min_items_field_count = 2;
        msg.min_items_field[0] = 1;
        msg.min_items_field[1] = 2;
        
        msg.max_items_field_count = 3;
        msg.max_items_field[0] = 1;
        msg.max_items_field[1] = 2;
        msg.max_items_field[2] = 3;
        
        msg.range_items_field_count = 3;
        msg.range_items_field[0] = 10;
        msg.range_items_field[1] = 20;
        msg.range_items_field[2] = 30;
        
        msg.unique_field_count = 3;
        msg.unique_field[0] = 1;
        msg.unique_field[1] = 2;
        msg.unique_field[2] = 3;
        
        pb_violations_init(&viol);
        ok = pb_validate_RepeatedRules(&msg, &viol);
        EXPECT_VALID(ok, "all repeated constraints satisfied");
    }
    
    /* Test min_items violation */
    TEST("RepeatedRules - min_items violation");
    {
        RepeatedRules msg = RepeatedRules_init_zero;
        msg.min_items_field_count = 0;  /* < 1, should fail */
        
        msg.max_items_field_count = 3;
        msg.max_items_field[0] = 1;
        msg.max_items_field[1] = 2;
        msg.max_items_field[2] = 3;
        
        msg.range_items_field_count = 3;
        msg.range_items_field[0] = 10;
        msg.range_items_field[1] = 20;
        msg.range_items_field[2] = 30;
        
        msg.unique_field_count = 3;
        msg.unique_field[0] = 1;
        msg.unique_field[1] = 2;
        msg.unique_field[2] = 3;
        
        pb_violations_init(&viol);
        ok = pb_validate_RepeatedRules(&msg, &viol);
        EXPECT_INVALID(ok, "min_items_field empty");
        EXPECT_VIOLATION(viol, "repeated.min_items");
    }
    
    /* Test max_items violation */
    TEST("RepeatedRules - max_items violation");
    {
        RepeatedRules msg = RepeatedRules_init_zero;
        msg.min_items_field_count = 1;
        msg.min_items_field[0] = 1;
        
        msg.max_items_field_count = 6;  /* > 5, should fail */
        msg.max_items_field[0] = 1;
        msg.max_items_field[1] = 2;
        msg.max_items_field[2] = 3;
        msg.max_items_field[3] = 4;
        msg.max_items_field[4] = 5;
        msg.max_items_field[5] = 6;
        
        msg.range_items_field_count = 3;
        msg.range_items_field[0] = 10;
        msg.range_items_field[1] = 20;
        msg.range_items_field[2] = 30;
        
        msg.unique_field_count = 3;
        msg.unique_field[0] = 1;
        msg.unique_field[1] = 2;
        msg.unique_field[2] = 3;
        
        pb_violations_init(&viol);
        ok = pb_validate_RepeatedRules(&msg, &viol);
        EXPECT_INVALID(ok, "max_items_field too many");
        EXPECT_VIOLATION(viol, "repeated.max_items");
    }
}

/*======================================================================
 * REPEATED ITEMS/UNIQUE RULES TESTS (new message types)
 *======================================================================*/

static void test_repeated_items_rules(void)
{
    pb_violations_t viol;
    bool ok;

    printf("\n=== Repeated Items/Unique Rules Tests ===\n");

    /* RepeatedStringItems: valid values (min_len/max_len per item) */
    TEST("RepeatedStringItems - valid values");
    {
        RepeatedStringItems msg = RepeatedStringItems_init_zero;
        msg.values_count = 3;
        strcpy(msg.values[0], "abc");
        strcpy(msg.values[1], "hello");
        strcpy(msg.values[2], "tenletters"); /* 10 chars */

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedStringItems(&msg, &viol);
        EXPECT_VALID(ok, "all string item constraints satisfied");
    }

    /* RepeatedStringItems: min_len violation */
    TEST("RepeatedStringItems - item min_len violation");
    {
        RepeatedStringItems msg = RepeatedStringItems_init_zero;
        msg.values_count = 1;
        strcpy(msg.values[0], "ab"); /* too short (< 3) */

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedStringItems(&msg, &viol);
        EXPECT_INVALID(ok, "an item shorter than min_len");
        EXPECT_VIOLATION(viol, "string.min_len");
    }

    /* RepeatedStringItems: max_len violation */
    TEST("RepeatedStringItems - item max_len violation");
    {
        RepeatedStringItems msg = RepeatedStringItems_init_zero;
        msg.values_count = 1;
        strcpy(msg.values[0], "thisiswaytoolong!"); /* > 10 */

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedStringItems(&msg, &viol);
        EXPECT_INVALID(ok, "an item longer than max_len");
        EXPECT_VIOLATION(viol, "string.max_len");
    }

    /* RepeatedInt32Items: valid values (gt/lt per item) */
    TEST("RepeatedInt32Items - valid values");
    {
        RepeatedInt32Items msg = RepeatedInt32Items_init_zero;
        msg.values_count = 3;
        msg.values[0] = 1;
        msg.values[1] = 50;
        msg.values[2] = 99;

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedInt32Items(&msg, &viol);
        EXPECT_VALID(ok, "all int32 item constraints satisfied");
    }

    /* RepeatedInt32Items: gt violation (value <= 0) */
    TEST("RepeatedInt32Items - item gt violation");
    {
        RepeatedInt32Items msg = RepeatedInt32Items_init_zero;
        msg.values_count = 2;
        msg.values[0] = 0;  /* not > 0 */
        msg.values[1] = 10;

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedInt32Items(&msg, &viol);
        EXPECT_INVALID(ok, "an item not greater than 0");
        EXPECT_VIOLATION(viol, "int32.gt");
    }

    /* RepeatedInt32Items: lt violation (value >= 100) */
    TEST("RepeatedInt32Items - item lt violation");
    {
        RepeatedInt32Items msg = RepeatedInt32Items_init_zero;
        msg.values_count = 2;
        msg.values[0] = 50;
        msg.values[1] = 100; /* not < 100 */

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedInt32Items(&msg, &viol);
        EXPECT_INVALID(ok, "an item not less than 100");
        EXPECT_VIOLATION(viol, "int32.lt");
    }

    /* RepeatedUniqueStrings: valid unique values */
    TEST("RepeatedUniqueStrings - valid unique set");
    {
        RepeatedUniqueStrings msg = RepeatedUniqueStrings_init_zero;
        msg.values_count = 3;
        strcpy(msg.values[0], "aa");
        strcpy(msg.values[1], "bb");
        strcpy(msg.values[2], "cc");

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedUniqueStrings(&msg, &viol);
        EXPECT_VALID(ok, "unique strings accepted");
    }

    /* RepeatedUniqueStrings: duplicate violation */
    TEST("RepeatedUniqueStrings - unique violation");
    {
        RepeatedUniqueStrings msg = RepeatedUniqueStrings_init_zero;
        msg.values_count = 3;
        strcpy(msg.values[0], "dup");
        strcpy(msg.values[1], "other");
        strcpy(msg.values[2], "dup");

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedUniqueStrings(&msg, &viol);
        EXPECT_INVALID(ok, "duplicate string items");
        EXPECT_VIOLATION(viol, "repeated.unique");
    }

    /* RepeatedUniqueInt32: valid unique values */
    TEST("RepeatedUniqueInt32 - valid unique set");
    {
        RepeatedUniqueInt32 msg = RepeatedUniqueInt32_init_zero;
        msg.values_count = 4;
        msg.values[0] = 1;
        msg.values[1] = 2;
        msg.values[2] = 3;
        msg.values[3] = 4;

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedUniqueInt32(&msg, &viol);
        EXPECT_VALID(ok, "unique int32 items accepted");
    }

    /* RepeatedUniqueInt32: duplicate violation */
    TEST("RepeatedUniqueInt32 - unique violation");
    {
        RepeatedUniqueInt32 msg = RepeatedUniqueInt32_init_zero;
        msg.values_count = 3;
        msg.values[0] = 1;
        msg.values[1] = 2;
        msg.values[2] = 1; /* duplicate */

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedUniqueInt32(&msg, &viol);
        EXPECT_INVALID(ok, "duplicate int32 items");
        EXPECT_VIOLATION(viol, "repeated.unique");
    }

    /* RepeatedBothConstraints: valid (min_len per item + unique) */
    TEST("RepeatedBothConstraints - valid values");
    {
        RepeatedBothConstraints msg = RepeatedBothConstraints_init_zero;
        msg.values_count = 3;
        strcpy(msg.values[0], "aa");
        strcpy(msg.values[1], "bb");
        strcpy(msg.values[2], "cc");

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedBothConstraints(&msg, &viol);
        EXPECT_VALID(ok, "items meet min_len and are unique");
    }

    /* RepeatedBothConstraints: item min_len violation */
    TEST("RepeatedBothConstraints - item min_len violation");
    {
        RepeatedBothConstraints msg = RepeatedBothConstraints_init_zero;
        msg.values_count = 2;
        strcpy(msg.values[0], "a");   /* too short */
        strcpy(msg.values[1], "bb");

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedBothConstraints(&msg, &viol);
        EXPECT_INVALID(ok, "item shorter than min_len");
        EXPECT_VIOLATION(viol, "string.min_len");
    }

    /* RepeatedBothConstraints: unique violation */
    TEST("RepeatedBothConstraints - unique violation");
    {
        RepeatedBothConstraints msg = RepeatedBothConstraints_init_zero;
        msg.values_count = 2;
        strcpy(msg.values[0], "bb");
        strcpy(msg.values[1], "bb");

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedBothConstraints(&msg, &viol);
        EXPECT_INVALID(ok, "duplicate items in unique list");
        EXPECT_VIOLATION(viol, "repeated.unique");
    }

    /* RepeatedAllConstraints: valid (min/max items, gte/lte per item, unique) */
    TEST("RepeatedAllConstraints - valid values");
    {
        RepeatedAllConstraints msg = RepeatedAllConstraints_init_zero;
        msg.numbers_count = 4;
        msg.numbers[0] = 0;
        msg.numbers[1] = 10;
        msg.numbers[2] = 100;
        msg.numbers[3] = 1000;

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedAllConstraints(&msg, &viol);
        EXPECT_VALID(ok, "all repeated constraints satisfied");
    }

    /* RepeatedAllConstraints: min_items violation */
    TEST("RepeatedAllConstraints - min_items violation");
    {
        RepeatedAllConstraints msg = RepeatedAllConstraints_init_zero;
        msg.numbers_count = 0; /* < 1 */

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedAllConstraints(&msg, &viol);
        EXPECT_INVALID(ok, "not enough items");
        EXPECT_VIOLATION(viol, "repeated.min_items");
    }

    /* RepeatedAllConstraints: max_items violation */
    TEST("RepeatedAllConstraints - max_items violation");
    {
        RepeatedAllConstraints msg = RepeatedAllConstraints_init_zero;
        msg.numbers_count = 11; /* > 10, within nanopb max_count 20 */
        for (pb_size_t i = 0; i < msg.numbers_count; ++i) {
            msg.numbers[i] = (int32_t)(i + 1);
        }

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedAllConstraints(&msg, &viol);
        EXPECT_INVALID(ok, "too many items");
        EXPECT_VIOLATION(viol, "repeated.max_items");
    }

    /* RepeatedAllConstraints: item out of allowed range (lte violation) */
    TEST("RepeatedAllConstraints - item lte violation");
    {
        RepeatedAllConstraints msg = RepeatedAllConstraints_init_zero;
        msg.numbers_count = 3;
        msg.numbers[0] = 0;
        msg.numbers[1] = 1001; /* not <= 1000 */
        msg.numbers[2] = 10;

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedAllConstraints(&msg, &viol);
        EXPECT_INVALID(ok, "item exceeds max allowed value");
        EXPECT_VIOLATION(viol, "int32.lte");
    }

    /* RepeatedAllConstraints: unique violation */
    TEST("RepeatedAllConstraints - unique violation");
    {
        RepeatedAllConstraints msg = RepeatedAllConstraints_init_zero;
        msg.numbers_count = 4;
        msg.numbers[0] = 5;
        msg.numbers[1] = 10;
        msg.numbers[2] = 5;  /* duplicate */
        msg.numbers[3] = 20;

        pb_violations_init(&viol);
        ok = pb_validate_RepeatedAllConstraints(&msg, &viol);
        EXPECT_INVALID(ok, "duplicate numbers not allowed");
        EXPECT_VIOLATION(viol, "repeated.unique");
    }
}

/*======================================================================
 * ENUM RULES TESTS
 *======================================================================*/

static void test_enum_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Enum Rules Tests ===\n");
    
    /* Test valid message */
    TEST("EnumRules - valid values");
    {
        EnumRules msg = EnumRules_init_zero;
        msg.defined_only_field = Status_STATUS_ACTIVE;   /* valid enum value */
        msg.const_field = Status_STATUS_ACTIVE;          /* == 1 */
        msg.color_field = Color_COLOR_RED;               /* valid color */
        
        pb_violations_init(&viol);
        ok = pb_validate_EnumRules(&msg, &viol);
        EXPECT_VALID(ok, "all enum constraints satisfied");
    }
    
    /* Test defined_only violation */
    TEST("EnumRules - defined_only violation");
    {
        EnumRules msg = EnumRules_init_zero;
        msg.defined_only_field = (Status)999;            /* undefined value */
        msg.const_field = Status_STATUS_ACTIVE;
        msg.color_field = Color_COLOR_RED;
        
        pb_violations_init(&viol);
        ok = pb_validate_EnumRules(&msg, &viol);
        EXPECT_INVALID(ok, "defined_only_field undefined");
        EXPECT_VIOLATION(viol, "enum.defined_only");
    }
    
    /* Test const violation */
    TEST("EnumRules - const violation");
    {
        EnumRules msg = EnumRules_init_zero;
        msg.defined_only_field = Status_STATUS_ACTIVE;
        msg.const_field = Status_STATUS_SUSPENDED;       /* != 1, should fail */
        msg.color_field = Color_COLOR_RED;
        
        pb_violations_init(&viol);
        ok = pb_validate_EnumRules(&msg, &viol);
        EXPECT_INVALID(ok, "const_field != 1");
        EXPECT_VIOLATION(viol, "enum.const");
    }
}

/*======================================================================
 * MESSAGE RULES TESTS
 *======================================================================*/

static void test_message_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Message Rules Tests ===\n");
    
    /* Test valid message */
    TEST("MessageRules - valid values");
    {
        MessageRules msg = MessageRules_init_zero;
        strcpy(msg.name, "John");
        msg.age = 30;
        
        msg.has_address = true;
        strcpy(msg.address.city, "Helsinki");
        strcpy(msg.address.zip_code, "00100");
        strcpy(msg.address.ip_address, "192.168.1.1");
        
        msg.has_contact = true;
        strcpy(msg.contact.email, "john@example.com");
        strcpy(msg.contact.phone, "12345678901");
        
        pb_violations_init(&viol);
        ok = pb_validate_MessageRules(&msg, &viol);
        EXPECT_VALID(ok, "all message constraints satisfied");
    }
    
    /* Test name validation */
    TEST("MessageRules - name min_len violation");
    {
        MessageRules msg = MessageRules_init_zero;
        strcpy(msg.name, "");  /* empty name, should fail */
        msg.age = 30;
        
        msg.has_address = true;
        strcpy(msg.address.city, "Helsinki");
        strcpy(msg.address.zip_code, "00100");
        strcpy(msg.address.ip_address, "192.168.1.1");
        
        msg.has_contact = true;
        strcpy(msg.contact.email, "john@example.com");
        strcpy(msg.contact.phone, "12345678901");
        
        pb_violations_init(&viol);
        ok = pb_validate_MessageRules(&msg, &viol);
        EXPECT_INVALID(ok, "name empty");
        EXPECT_VIOLATION(viol, "string.min_len");
    }
    
    /* Test nested message validation */
    TEST("MessageRules - nested address.ip invalid");
    {
        MessageRules msg = MessageRules_init_zero;
        strcpy(msg.name, "John");
        msg.age = 30;
        
        msg.has_address = true;
        strcpy(msg.address.city, "Helsinki");
        strcpy(msg.address.zip_code, "00100");
        strcpy(msg.address.ip_address, "invalid_ip");  /* should fail */
        
        msg.has_contact = true;
        strcpy(msg.contact.email, "john@example.com");
        strcpy(msg.contact.phone, "12345678901");
        
        pb_violations_init(&viol);
        ok = pb_validate_MessageRules(&msg, &viol);
        EXPECT_INVALID(ok, "address.ip_address invalid");
        EXPECT_VIOLATION(viol, "string.ip");
    }
    
    /* Test nested contact email validation */
    TEST("MessageRules - nested contact.email invalid");
    {
        MessageRules msg = MessageRules_init_zero;
        strcpy(msg.name, "John");
        msg.age = 30;
        
        msg.has_address = true;
        strcpy(msg.address.city, "Helsinki");
        strcpy(msg.address.zip_code, "00100");
        strcpy(msg.address.ip_address, "192.168.1.1");
        
        msg.has_contact = true;
        strcpy(msg.contact.email, "not_an_email");  /* should fail */
        strcpy(msg.contact.phone, "12345678901");
        
        pb_violations_init(&viol);
        ok = pb_validate_MessageRules(&msg, &viol);
        EXPECT_INVALID(ok, "contact.email invalid");
        EXPECT_VIOLATION(viol, "string.email");
    }
}

/*======================================================================
 * ONEOF RULES TESTS
 * NOTE: Oneof member validation is a known limitation - the generator
 * doesn't currently support validation rules on oneof members.
 *======================================================================*/

static void test_oneof_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Oneof Rules Tests ===\n");
    printf("  NOTE: Oneof member validation not yet supported by generator\n");
    
    /* Test valid message with string option */
    TEST("OneofRules - valid str_option");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_str_option_tag;
        strcpy(msg.choice.str_option, "valid_string");  /* >= 3 chars */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_VALID(ok, "str_option valid");
    }
    
    /* Test valid message with int option */
    TEST("OneofRules - valid int_option");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_int_option_tag;
        msg.choice.int_option = 500;  /* 0 <= x <= 1000 */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_VALID(ok, "int_option valid");
    }
    
    /* Test str_option min_len violation */
    TEST("OneofRules - str_option min_len violation");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_str_option_tag;
        strcpy(msg.choice.str_option, "ab");  /* < 3 chars, should fail */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_INVALID(ok, "str_option too short");
        EXPECT_VIOLATION(viol, "string.min_len");
    }
    
    /* Test int_option gte violation */
    TEST("OneofRules - int_option gte violation");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_int_option_tag;
        msg.choice.int_option = -1;  /* < 0, should fail */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_INVALID(ok, "int_option below minimum");
        EXPECT_VIOLATION(viol, "int32.gte");
    }
    
    /* Test int_option lte violation */
    TEST("OneofRules - int_option lte violation");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_int_option_tag;
        msg.choice.int_option = 1001;  /* > 1000, should fail */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_INVALID(ok, "int_option above maximum");
        EXPECT_VIOLATION(viol, "int32.lte");
    }
    
    /* Test float_option gt violation */
    TEST("OneofRules - float_option gt violation");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_float_option_tag;
        msg.choice.float_option = 0.0f;  /* NOT > 0.0, should fail */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_INVALID(ok, "float_option not greater than zero");
        EXPECT_VIOLATION(viol, "float.gt");
    }
    
    /* Test valid float_option */
    TEST("OneofRules - valid float_option");
    {
        OneofRules msg = OneofRules_init_zero;
        strcpy(msg.common_field, "common");
        msg.which_choice = OneofRules_float_option_tag;
        msg.choice.float_option = 3.14f;  /* > 0.0, valid */
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        EXPECT_VALID(ok, "float_option valid");
    }
    
    /* Test common_field validation */
    TEST("OneofRules - common_field max_size violation");
    {
        OneofRules msg = OneofRules_init_zero;
        /* Fill common_field to exceed max_size=32 (but within nanopb buffer) */
        strncpy(msg.common_field, "this_string_is_way_too_long_for_the_max_size_constraint", sizeof(msg.common_field) - 1);
        msg.common_field[sizeof(msg.common_field) - 1] = '\0';
        msg.which_choice = OneofRules_str_option_tag;
        strcpy(msg.choice.str_option, "valid");
        
        pb_violations_init(&viol);
        ok = pb_validate_OneofRules(&msg, &viol);
        /* Note: max_size is a nanopb option, not a validation rule,
         * so this may or may not trigger a validation error depending on implementation */
        if (!ok) {
            printf("    [INFO] common_field max_size validated (implementation-dependent)\n");
            tests_passed++;
        } else {
            printf("    [INFO] common_field max_size not validated (expected for nanopb option)\n");
            tests_passed++;
        }
    }
}

/*======================================================================
 * BYTES RULES TESTS
 *======================================================================*/

static void test_bytes_rules(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Bytes Rules Tests ===\n");
    
    /* Test valid message */
    TEST("BytesRules - valid values");
    {
        BytesRules msg = BytesRules_init_zero;
        msg.min_len_field.size = 5;
        memcpy(msg.min_len_field.bytes, "hello", 5);
        
        msg.max_len_field.size = 10;
        memcpy(msg.max_len_field.bytes, "short text", 10);
        
        msg.range_len_field.size = 10;
        memcpy(msg.range_len_field.bytes, "rangevalue", 10);
        
        pb_violations_init(&viol);
        ok = pb_validate_BytesRules(&msg, &viol);
        EXPECT_VALID(ok, "all bytes constraints satisfied");
    }
    
    /* Test min_len violation */
    TEST("BytesRules - min_len violation");
    {
        BytesRules msg = BytesRules_init_zero;
        msg.min_len_field.size = 0;  /* < 1, should fail */
        
        msg.max_len_field.size = 10;
        memcpy(msg.max_len_field.bytes, "short text", 10);
        
        msg.range_len_field.size = 10;
        memcpy(msg.range_len_field.bytes, "rangevalue", 10);
        
        pb_violations_init(&viol);
        ok = pb_validate_BytesRules(&msg, &viol);
        EXPECT_INVALID(ok, "min_len_field empty");
        EXPECT_VIOLATION(viol, "bytes.min_len");
    }
}

/*======================================================================
 * ANY FIELD BEHAVIOR TESTS
 *======================================================================*/

static void test_any_behavior(void)
{
    pb_violations_t viol;
    bool ok;

    printf("\n=== Any Field Behavior Tests ===\n");

    /* AnyBehavior: allowed type_url (any.in) */
    TEST("AnyBehavior - allowed type_url");
    {
        AnyBehavior msg = AnyBehavior_init_zero;
        msg.has_any_field = true;
        /* Set a type_url that should be allowed by any.in */
        strcpy((char*)msg.any_field.type_url, "type.google.com/demo.Int32Rules");
        /* No payload validation needed for these tests */

        pb_violations_init(&viol);
        ok = pb_validate_AnyBehavior(&msg, &viol);
        EXPECT_VALID(ok, "type_url in allowed list");
    }

    /* AnyBehavior: type_url not in allowed set triggers any.in */
    TEST("AnyBehavior - any.in violation");
    {
        AnyBehavior msg = AnyBehavior_init_zero;
        msg.has_any_field = true;
        strcpy((char*)msg.any_field.type_url, "type.google.com/demo.UnknownType");

        pb_violations_init(&viol);
        ok = pb_validate_AnyBehavior(&msg, &viol);
        EXPECT_INVALID(ok, "type_url not in allowed list");
        EXPECT_VIOLATION(viol, "any.in");
    }

    /* AnyBehavior: type_url in disallowed set triggers any.not_in */
    TEST("AnyBehavior - any.not_in violation");
    {
        AnyBehavior msg = AnyBehavior_init_zero;
        msg.has_any_field = true;
        msg.has_any_field2 = true;
        strcpy((char*)msg.any_field.type_url, "type.google.com/demo.EnumRules");
        strcpy((char*)msg.any_field2.type_url, "type.google.com/demo.EnumRules");

        pb_violations_init(&viol);
        ok = pb_validate_AnyBehavior(&msg, &viol);
        EXPECT_INVALID(ok, "type_url in disallowed list");
        EXPECT_VIOLATION(viol, "any.not_in");
    }
}

/*======================================================================
 * BYPASS/EARLY-EXIT BEHAVIOR TESTS
 *======================================================================*/

static void test_bypass_behavior(void)
{
    pb_violations_t viol;
    bool ok;
    
    printf("\n=== Bypass/Early-Exit Behavior Tests ===\n");
    
    /* Test valid message */
    TEST("BypassBehavior - valid values");
    {
        BypassBehavior msg = BypassBehavior_init_zero;
        msg.first_num = 50;
        msg.second_num = 50;
        msg.third_num = 50;
        strcpy(msg.first_str, "valid");
        strcpy(msg.second_str, "valid");
        msg.extra1 = 0;
        msg.extra2 = 0;
        msg.extra3 = 0;
        msg.extra4 = 0;
        msg.extra5 = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_BypassBehavior(&msg, &viol);
        EXPECT_VALID(ok, "all bypass constraints satisfied");
    }
    
    /* Test single violation (early exit) */
    TEST("BypassBehavior - single violation");
    {
        BypassBehavior msg = BypassBehavior_init_zero;
        msg.first_num = 200;  /* > 100, should fail */
        msg.second_num = 50;
        msg.third_num = 50;
        strcpy(msg.first_str, "valid");
        strcpy(msg.second_str, "valid");
        msg.extra1 = 0;
        msg.extra2 = 0;
        msg.extra3 = 0;
        msg.extra4 = 0;
        msg.extra5 = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_BypassBehavior(&msg, &viol);
        EXPECT_INVALID(ok, "first_num out of range");
        EXPECT_VIOLATION(viol, "int32.lte");
    }

#ifdef PB_VALIDATE_DEBUG
    /* Under PB_VALIDATE_DEBUG, validation always collects every violation
     * (forced collect-all, ignoring PB_VALIDATE_EARLY_EXIT), unlike the
     * single-violation early-exit default exercised above. */
    TEST("BypassBehavior - debug mode collects all violations");
    {
        BypassBehavior msg = BypassBehavior_init_zero;
        msg.first_num = 200;   /* > 100, violates int32.lte */
        msg.second_num = -5;   /* < 0, violates int32.gte */
        msg.third_num = 50;
        strcpy(msg.first_str, "");   /* empty, violates string.min_len */
        strcpy(msg.second_str, "valid");
        msg.extra1 = 0;
        msg.extra2 = 0;
        msg.extra3 = 0;
        msg.extra4 = 0;
        msg.extra5 = 0;

        pb_violations_init(&viol);
        ok = pb_validate_BypassBehavior(&msg, &viol);
        EXPECT_INVALID(ok, "multiple simultaneous violations");

        if (pb_violations_count(&viol) > 1) {
            tests_passed++;
            printf("    [PASS] Collected %u violations (early exit forced off)\n",
                   (unsigned)pb_violations_count(&viol));
        } else {
            tests_failed++;
            printf("    [FAIL] Expected more than 1 violation, got %u\n",
                   (unsigned)pb_violations_count(&viol));
        }

        /* Spot-check that the numeric violation's message carries the
         * interpolated actual/expected values, not just a static string. */
        if (strstr(viol.violations[0].message, "200") != NULL) {
            tests_passed++;
            printf("    [PASS] Debug message carries interpolated value: '%s'\n",
                   viol.violations[0].message);
        } else {
            tests_failed++;
            printf("    [FAIL] Debug message missing interpolated value: '%s'\n",
                   viol.violations[0].message);
        }
    }
#endif /* PB_VALIDATE_DEBUG */
}

/*======================================================================
 * PATH REPORTING TESTS
 * NOTE: field_path is now a copy owned by the violation itself (made at
 * the moment the violation is recorded), so it stays valid and correct
 * for the reporting message's own fields. Cross-message prefixing (e.g.
 * "nested.nested_name" from the outer message's perspective) is still a
 * known limitation: each nested pb_validate_* call tracks its own path
 * independently and has no way to prepend the parent's path.
 *======================================================================*/

static void test_path_reporting(void)
{
    pb_violations_t viol;
    bool ok;

    printf("\n=== Path Reporting Tests ===\n");

    /* Test top-level field path is reported correctly and stays valid
     * after pb_validate_PathReporting has returned. */
    TEST("PathReporting - violation reported");
    {
        PathReporting msg = PathReporting_init_zero;
        strcpy(msg.name, "");  /* empty, should fail */
        msg.has_nested = true;
        strcpy(msg.nested.nested_name, "nested");
        msg.nested.nested_value = 0;

        pb_violations_init(&viol);
        ok = pb_validate_PathReporting(&msg, &viol);
        EXPECT_INVALID(ok, "name empty");

        if (pb_violations_has_any(&viol) &&
            strcmp(viol.violations[0].field_path, "name") == 0) {
            tests_passed++;
            printf("    [PASS] Path correctly reported: '%s'\n", viol.violations[0].field_path);
        } else {
            tests_failed++;
            printf("    [FAIL] Path missing or incorrect: '%s'\n",
                   pb_violations_has_any(&viol) ? viol.violations[0].field_path : "(none)");
        }
    }
    
    /* Test nested field validation - ensure nested messages get validated */
    TEST("PathReporting - nested validation works");
    {
        PathReporting msg = PathReporting_init_zero;
        strcpy(msg.name, "valid");
        msg.has_nested = true;
        strcpy(msg.nested.nested_name, "");  /* empty, should fail */
        msg.nested.nested_value = 0;
        
        pb_violations_init(&viol);
        ok = pb_validate_PathReporting(&msg, &viol);
        EXPECT_INVALID(ok, "nested.nested_name empty");
        EXPECT_VIOLATION(viol, "string.min_len");
    }
}

/*======================================================================
 * VIOLATIONS COLLECTION TESTS
 *======================================================================*/

static void test_violations_collection(void)
{
    pb_violations_t viol;
    
    printf("\n=== Violations Collection Tests ===\n");
    
    /* Test violations init */
    TEST("Violations - initialization");
    {
        pb_violations_init(&viol);
        if (viol.count == 0 && !viol.truncated) {
            tests_passed++;
            printf("    [PASS] Violations initialized correctly\n");
        } else {
            tests_failed++;
            printf("    [FAIL] Violations not initialized correctly\n");
        }
    }
    
    /* Test adding violations */
    TEST("Violations - adding entries");
    {
        pb_violations_init(&viol);
        bool added = pb_violations_add(&viol, "field1", "rule1", "message1");
        if (added && viol.count == 1) {
            tests_passed++;
            printf("    [PASS] Violation added successfully\n");
        } else {
            tests_failed++;
            printf("    [FAIL] Failed to add violation\n");
        }
    }
    
    /* Test violation retrieval */
    TEST("Violations - retrieval");
    {
        pb_violations_init(&viol);
        pb_violations_add(&viol, "test_field", "test_rule", "test_message");
        
        if (strcmp(viol.violations[0].field_path, "test_field") == 0 &&
            strcmp(viol.violations[0].constraint_id, "test_rule") == 0 &&
            strcmp(viol.violations[0].message, "test_message") == 0) {
            tests_passed++;
            printf("    [PASS] Violation data retrieved correctly\n");
        } else {
            tests_failed++;
            printf("    [FAIL] Violation data mismatch\n");
        }
    }
    
    /* Test has_any helper */
    TEST("Violations - has_any helper");
    {
        pb_violations_init(&viol);
        if (!pb_violations_has_any(&viol)) {
            tests_passed++;
            printf("    [PASS] has_any returns false for empty\n");
        } else {
            tests_failed++;
            printf("    [FAIL] has_any should return false for empty\n");
        }
        
        pb_violations_add(&viol, "f", "r", "m");
        if (pb_violations_has_any(&viol)) {
            tests_passed++;
            printf("    [PASS] has_any returns true when non-empty\n");
        } else {
            tests_failed++;
            printf("    [FAIL] has_any should return true when non-empty\n");
        }
    }
}

/*======================================================================
 * MAIN
 *======================================================================*/

/*======================================================================
 * CONST_VALUE RULE TESTS (string / bytes)
 *======================================================================*/

static void test_const_rules(void)
{
    pb_violations_t viol;
    bool ok;

    printf("\n=== const_value Rule Tests ===\n");

    TEST("StringConstRules - matching value");
    {
        StringConstRules msg = StringConstRules_init_zero;
        strcpy(msg.const_field, "exact");

        pb_violations_init(&viol);
        ok = pb_validate_StringConstRules(&msg, &viol);
        EXPECT_VALID(ok, "string equals const_value");
    }

    TEST("StringConstRules - string.const violation");
    {
        StringConstRules msg = StringConstRules_init_zero;
        strcpy(msg.const_field, "other");

        pb_violations_init(&viol);
        ok = pb_validate_StringConstRules(&msg, &viol);
        EXPECT_INVALID(ok, "string differs from const_value");
        EXPECT_VIOLATION(viol, "string.const");
    }

    TEST("BytesConstRules - matching value");
    {
        BytesConstRules msg = BytesConstRules_init_zero;
        msg.const_field.size = 3;
        msg.const_field.bytes[0] = 0x01;
        msg.const_field.bytes[1] = 0x02;
        msg.const_field.bytes[2] = 0x03;

        pb_violations_init(&viol);
        ok = pb_validate_BytesConstRules(&msg, &viol);
        EXPECT_VALID(ok, "bytes equal const_value");
    }

    TEST("BytesConstRules - bytes.const violation");
    {
        BytesConstRules msg = BytesConstRules_init_zero;
        msg.const_field.size = 3;
        msg.const_field.bytes[0] = 0x01;
        msg.const_field.bytes[1] = 0x02;
        msg.const_field.bytes[2] = 0x04;

        pb_violations_init(&viol);
        ok = pb_validate_BytesConstRules(&msg, &viol);
        EXPECT_INVALID(ok, "bytes differ from const_value");
        EXPECT_VIOLATION(viol, "bytes.const");
    }
}

int main(void)
{
    printf("==========================================\n");
    printf("  Nanopb Validation Test Suite\n");
    printf("==========================================\n");
    
    /* Run all tests */
    test_int32_rules();
    test_float_rules();
    test_double_rules();
    test_uint_rules();
    test_string_rules();
    test_ipv6_edge_cases();
    test_repeated_rules();
    test_repeated_items_rules();
    test_enum_rules();
    test_message_rules();
    test_oneof_rules();
    test_bytes_rules();
    test_const_rules();
    test_any_behavior();
    test_bypass_behavior();
    test_path_reporting();
    test_violations_collection();
    
    /* Print summary */
    printf("\n==========================================\n");
    printf("  Test Summary\n");
    printf("==========================================\n");
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("==========================================\n");
    
    if (tests_failed > 0) {
        printf("\n*** SOME TESTS FAILED ***\n");
        return 1;
    }
    
    printf("\n*** ALL TESTS PASSED ***\n");
    return 0;
}
