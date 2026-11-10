# Nested Import Validation Test

## Overview

This test specifically verifies that nanopb's validation code generator correctly handles cross-file validation when proto files import each other. It ensures that validation functions from different `*_validate.c` files integrate seamlessly and call each other correctly at runtime.

## Test Structure

### Proto Files

1. **child.proto**
   - Defines `ChildProfile` message with validation rules:
     - `name`: non-empty string
     - `age`: 0-18 range
     - `email`: valid email format
   - Defines `ChildAddress` message with validation rules:
     - `street`: non-empty string
     - `city`: minimum 2 characters
     - `zip_code`: 5-10 characters

2. **parent.proto**
   - Imports `child.proto`
   - Defines `ParentRecord` message that:
     - Contains nested `ChildProfile` and `ChildAddress` fields
     - Has its own validation rules for parent-level fields
   - Defines `ParentContainer` message for testing deep nesting:
     - Contains `ParentRecord` which contains child messages
     - Tests multi-level validation chains

### Test File

**test_nested_import.c** contains 16 comprehensive test cases:

#### Child-Level Tests (7 tests)
- Valid child profile and address
- Invalid child profile (empty name, age out of range, bad email)
- Invalid child address (empty street, short city)

#### Parent-Level Cross-File Tests (5 tests)
- Valid parent record with valid children
- Parent with invalid child profile (nested validation triggered)
- Parent with invalid address (nested validation triggered)
- Invalid parent name (parent's own rules)
- Invalid parent ID (parent's own rules)

#### Deep Nesting Tests (4 tests)
- Valid container with nested parent and children
- Container with invalid deeply nested child
- Invalid container-level fields

## What This Test Validates

### 1. Code Generation
- `parent_validate.h` correctly includes `child_validate.h`
- Generated validation functions have proper declarations
- Include paths are resolved correctly

### 2. Cross-File Function Calls
- `pb_validate_ParentRecord()` calls `pb_validate_ChildProfile()`
- `pb_validate_ParentRecord()` calls `pb_validate_ChildAddress()`
- `pb_validate_ParentContainer()` calls `pb_validate_ParentRecord()`
- Validation flows through multiple levels correctly

### 3. Validation Semantics
- Parent validation fails when nested child validation fails
- Parent validation can independently fail on parent-level rules
- Deep nesting (Container → Record → Child) works correctly
- Optional nested messages are validated when present

## Key Implementation Details

### nanopb_validator.py Enhancement

The validator generator was enhanced with the `_collect_validation_dependencies()` method that:
1. Analyzes all message fields in the proto file
2. Identifies MESSAGE-type fields from imported proto files
3. Generates appropriate `#include` directives for validation headers

This ensures that `parent_validate.h` automatically includes:
```c
#include "child_validate.h"
```

### Generated Validation Code

For a parent message containing a child message, the generator produces:

```c
bool pb_validate_ParentRecord(const ParentRecord *msg, pb_violations_t *violations)
{
    // ... parent field validations ...
    
    PB_VALIDATE_FIELD_BEGIN(ctx, "child");
    PB_VALIDATE_NESTED_MSG_OPTIONAL(ctx, pb_validate_ChildProfile, msg, child, violations);
    PB_VALIDATE_FIELD_END(ctx);
    
    // ... more validations ...
}
```

The macro `PB_VALIDATE_NESTED_MSG_OPTIONAL` checks if the optional field is present (`has_child`) and calls the child's validation function.

## Running the Test

```bash
cd tests
scons validation
```

The test runs as part of the validation test suite and will output:
```
===================================================
Nested Import Validation Test
Testing cross-file validation integration
===================================================
...
Test Results: 16 passed, 0 failed
===================================================
```

## Importance

This test is critical for real-world usage where:
- Projects organize proto files into logical modules
- Messages naturally reference types from other proto files
- Validation must work transparently across file boundaries
- Build systems need reliable cross-file dependency handling

Without proper cross-file validation support, users would need to manually ensure validation calls chain correctly, which is error-prone and defeats the purpose of code generation.
