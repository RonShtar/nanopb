/*
 * Nested Import Validation Test
 * 
 * This test specifically verifies that validation across imported proto files
 * works correctly. It tests:
 * 
 * 1. Cross-file validation: parent_validate.c calls child_validate.c
 * 2. Valid scenario: Both parent and child messages pass validation
 * 3. Invalid child: Parent validation detects violations in nested child message
 * 4. Invalid parent: Parent's own fields violate rules while child is valid
 * 5. Deep nesting: ParentContainer -> ParentRecord -> ChildProfile/ChildAddress
 * 
 * The goal is to ensure that generated validation functions from different
 * *_validate.c files integrate and call each other correctly at runtime.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pb.h"
#include "pb_validate.h"

/* Include generated headers from both proto files */
#include "child.pb.h"
#include "child_validate.h"
#include "parent.pb.h"
#include "parent_validate.h"

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

/* Helper functions to construct test data */

static void init_valid_child_profile(ChildProfile *profile)
{
    memset(profile, 0, sizeof(ChildProfile));
    strcpy(profile->name, "Alice");
    profile->age = 10;
    strcpy(profile->email, "alice@example.com");
}

static void init_valid_child_address(ChildAddress *addr)
{
    memset(addr, 0, sizeof(ChildAddress));
    strcpy(addr->street, "123 Main St");
    strcpy(addr->city, "Springfield");
    strcpy(addr->zip_code, "12345");
}

static void init_valid_parent_record(ParentRecord *record)
{
    memset(record, 0, sizeof(ParentRecord));
    strcpy(record->parent_name, "Parent");
    record->parent_id = 42;
    record->has_child = true;
    init_valid_child_profile(&record->child);
    record->has_address = true;
    init_valid_child_address(&record->address);
    strcpy(record->notes, "Test notes");
}

static void init_valid_parent_container(ParentContainer *container)
{
    memset(container, 0, sizeof(ParentContainer));
    strcpy(container->container_name, "Container1");
    container->has_record = true;
    init_valid_parent_record(&container->record);
    container->count = 5;
}

/* Test 1: Valid child profile validates successfully */
static void test_valid_child_profile(void)
{
    TEST("Valid ChildProfile validates");
    
    ChildProfile profile;
    init_valid_child_profile(&profile);
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildProfile(&profile, &violations);
    
    EXPECT_VALID(result, "Valid child profile");
}

/* Test 2: Invalid child profile (empty name) is rejected */
static void test_invalid_child_profile_empty_name(void)
{
    TEST("Invalid ChildProfile (empty name) rejected");
    
    ChildProfile profile;
    init_valid_child_profile(&profile);
    profile.name[0] = '\0';  /* Empty name violates min_len = 1 */
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildProfile(&profile, &violations);
    
    EXPECT_INVALID(result, "Empty name");
}

/* Test 3: Invalid child profile (age out of range) is rejected */
static void test_invalid_child_profile_age(void)
{
    TEST("Invalid ChildProfile (age > 18) rejected");
    
    ChildProfile profile;
    init_valid_child_profile(&profile);
    profile.age = 25;  /* Age > 18 violates child constraint */
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildProfile(&profile, &violations);
    
    EXPECT_INVALID(result, "Age out of range");
}

/* Test 4: Invalid child profile (bad email) is rejected */
static void test_invalid_child_profile_email(void)
{
    TEST("Invalid ChildProfile (bad email) rejected");
    
    ChildProfile profile;
    init_valid_child_profile(&profile);
    strcpy(profile.email, "not-an-email");  /* Invalid email format */
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildProfile(&profile, &violations);
    
    EXPECT_INVALID(result, "Invalid email");
}

/* Test 5: Valid child address validates successfully */
static void test_valid_child_address(void)
{
    TEST("Valid ChildAddress validates");
    
    ChildAddress addr;
    init_valid_child_address(&addr);
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildAddress(&addr, &violations);
    
    EXPECT_VALID(result, "Valid child address");
}

/* Test 6: Invalid child address (empty street) is rejected */
static void test_invalid_child_address_street(void)
{
    TEST("Invalid ChildAddress (empty street) rejected");
    
    ChildAddress addr;
    init_valid_child_address(&addr);
    addr.street[0] = '\0';  /* Empty street violates min_len = 1 */
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildAddress(&addr, &violations);
    
    EXPECT_INVALID(result, "Empty street");
}

/* Test 7: Invalid child address (short city) is rejected */
static void test_invalid_child_address_city(void)
{
    TEST("Invalid ChildAddress (city too short) rejected");
    
    ChildAddress addr;
    init_valid_child_address(&addr);
    strcpy(addr.city, "X");  /* City < 2 chars violates min_len = 2 */
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ChildAddress(&addr, &violations);
    
    EXPECT_INVALID(result, "City too short");
}

/* Test 8: Valid parent record validates (tests cross-file validation) */
static void test_valid_parent_record(void)
{
    TEST("Valid ParentRecord validates (cross-file)");
    
    ParentRecord record;
    init_valid_parent_record(&record);
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentRecord(&record, &violations);
    
    EXPECT_VALID(result, "Valid parent record with valid children");
}

/* Test 9: Parent record with invalid child is rejected */
static void test_parent_with_invalid_child(void)
{
    TEST("ParentRecord with invalid child rejected");
    
    ParentRecord record;
    init_valid_parent_record(&record);
    
    /* Make child profile invalid (empty name) */
    record.child.name[0] = '\0';
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentRecord(&record, &violations);
    
    EXPECT_INVALID(result, "Invalid nested child profile");
}

/* Test 10: Parent record with invalid address is rejected */
static void test_parent_with_invalid_address(void)
{
    TEST("ParentRecord with invalid address rejected");
    
    ParentRecord record;
    init_valid_parent_record(&record);
    
    /* Make child address invalid (empty street) */
    record.address.street[0] = '\0';
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentRecord(&record, &violations);
    
    EXPECT_INVALID(result, "Invalid nested child address");
}

/* Test 11: Invalid parent (short name) with valid children is rejected */
static void test_invalid_parent_name(void)
{
    TEST("ParentRecord with short parent_name rejected");
    
    ParentRecord record;
    init_valid_parent_record(&record);
    
    /* Make parent's own field invalid (name too short) */
    strcpy(record.parent_name, "X");  /* < 2 chars violates min_len = 2 */
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentRecord(&record, &violations);
    
    EXPECT_INVALID(result, "Parent name too short");
}

/* Test 12: Invalid parent (bad ID) with valid children is rejected */
static void test_invalid_parent_id(void)
{
    TEST("ParentRecord with parent_id <= 0 rejected");
    
    ParentRecord record;
    init_valid_parent_record(&record);
    
    /* Make parent's own field invalid (ID must be > 0) */
    record.parent_id = 0;
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentRecord(&record, &violations);
    
    EXPECT_INVALID(result, "Parent ID must be positive");
}

/* Test 13: Valid parent container validates (deep nesting) */
static void test_valid_parent_container(void)
{
    TEST("Valid ParentContainer validates (deep nesting)");
    
    ParentContainer container;
    init_valid_parent_container(&container);
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentContainer(&container, &violations);
    
    EXPECT_VALID(result, "Valid container with nested parent and children");
}

/* Test 14: Container with invalid nested child is rejected */
static void test_container_with_invalid_nested_child(void)
{
    TEST("ParentContainer with invalid nested child rejected");
    
    ParentContainer container;
    init_valid_parent_container(&container);
    
    /* Make deeply nested child invalid (age out of range) */
    container.record.child.age = 99;
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentContainer(&container, &violations);
    
    EXPECT_INVALID(result, "Invalid deeply nested child");
}

/* Test 15: Container with invalid container-level field is rejected */
static void test_invalid_container_name(void)
{
    TEST("ParentContainer with empty container_name rejected");
    
    ParentContainer container;
    init_valid_parent_container(&container);
    
    /* Make container's own field invalid (empty name) */
    container.container_name[0] = '\0';
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentContainer(&container, &violations);
    
    EXPECT_INVALID(result, "Empty container name");
}

/* Test 16: Container with negative count is rejected */
static void test_invalid_container_count(void)
{
    TEST("ParentContainer with negative count rejected");
    
    ParentContainer container;
    init_valid_parent_container(&container);
    
    /* Make container's count invalid (< 0) */
    container.count = -1;
    
    pb_violations_t violations;
    pb_violations_init(&violations);
    bool result = pb_validate_ParentContainer(&container, &violations);
    
    EXPECT_INVALID(result, "Negative count");
}

int main(void)
{
    printf("===================================================\n");
    printf("Nested Import Validation Test\n");
    printf("Testing cross-file validation integration\n");
    printf("===================================================\n\n");
    
    printf("Child Profile Tests:\n");
    test_valid_child_profile();
    test_invalid_child_profile_empty_name();
    test_invalid_child_profile_age();
    test_invalid_child_profile_email();
    
    printf("\nChild Address Tests:\n");
    test_valid_child_address();
    test_invalid_child_address_street();
    test_invalid_child_address_city();
    
    printf("\nParent Record Tests (cross-file validation):\n");
    test_valid_parent_record();
    test_parent_with_invalid_child();
    test_parent_with_invalid_address();
    test_invalid_parent_name();
    test_invalid_parent_id();
    
    printf("\nDeep Nesting Tests:\n");
    test_valid_parent_container();
    test_container_with_invalid_nested_child();
    test_invalid_container_name();
    test_invalid_container_count();
    
    printf("\n===================================================\n");
    printf("Test Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("===================================================\n");
    
    return (tests_failed == 0) ? 0 : 1;
}
