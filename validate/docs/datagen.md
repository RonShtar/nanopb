# Nanopb Data Generator

A Python module for generating valid and invalid protobuf test data based on validation constraints defined using `validate.proto`.

## Features

- 📝 **Parse validation rules** from `.proto` files
- ✅ **Generate valid data** that satisfies all constraints
- ❌ **Generate invalid data** that violates specific constraints
- 🔢 **Multiple output formats**: Binary, C arrays, hex strings
- 🎲 **Reproducible** with random seeds
- 🎯 **Type-safe** with full validation rule support

## Supported Validation Rules

### Numeric Types (int32, int64, uint32, uint64, sint32, sint64, fixed32, fixed64, sfixed32, sfixed64, float, double)
- `gt` / `gte` / `lt` / `lte` - Bounds (floats are stepped to the next
  representable `float`/`double`, so `gt`/`lt` hold after rounding)
- `const` - Exact value
- `in` / `not_in` - Value must (not) be in list

### String/Bytes
- `min_len` / `max_len` - Length limits in bytes (like the C validator)
- `const`, `in`, `not_in`
- `prefix`, `suffix`, `contains`
- `ascii`, `email`, `hostname`, `ip`, `ipv4`, `ipv6` (strings)

### Enums
- `const`, `in`, `not_in`, `defined_only`

### Repeated Fields and Maps
- `min_items` / `max_items` (`map.min_pairs` / `map.max_pairs`)
- `unique`
- `items` - per-entry rules, e.g. `repeated.items.int32.gt`. Violate them with
  `violate_rule='items.gt'`.

### Boolean
- `const` - Exact value

### Messages, oneofs and well-known types
- `required` / `oneof_required`
- `google.protobuf.Any`: `any.in` / `any.not_in`. The payload is a real
  message of the allowed type, serialised into `Any.value`
- `google.protobuf.Timestamp`: `gt_now`, `lt_now`, `within`; plain
  `Timestamp`/`Duration` values are always in the legal protobuf range
- `validate.message`: `requires`, `mutex`, `at_least`

A oneof carries exactly one generated member, so the dictionary returned by
`generate_valid()` is what gets encoded.

## nanopb Storage Limits

Data that satisfies `validate.proto` can still be undecodable on the target:
`pb_decode()` fails with `string overflow`, `bytes overflow`, `array overflow`
or `integer too large` as soon as a value does not fit the C struct. The
generator therefore reads the same nanopb options the nanopb generator uses
and keeps **valid and invalid** data inside them:

| Option | Effect on generated data |
| --- | --- |
| `max_size` / `max_length` | strings (`max_size - 1` characters) and bytes never exceed the buffer; `bytes` with `fixed_length` are exactly `max_size` long |
| `max_count` | repeated fields and maps never hold more entries; `fixed_count` arrays are always full |
| `int_size` | integers stay inside `int8_t`/`int16_t`/... of the generated field |
| `type: FT_CALLBACK` / `FT_POINTER` | no static buffer, so no size limit is applied |
| `google.protobuf.Any` `type_url` / `value` `max_size` | `Any` payloads that do not fit are never chosen |

Options are picked up from, in nanopb's order of precedence (later wins):

1. `<name>.options` next to every `.proto` (and below `-I` include paths), with
   wildcard masks such as `Message.*`, also for imported files such as
   `google/protobuf/any.options`;
2. extra files given with `DataGenerator(..., options_files=[...])` or `-f FILE`;
3. `(nanopb).max_size = ...` written in the `.proto` itself.

If the rules and the storage cannot both be satisfied (for example
`min_len = 40` for a field with `max_size = 8`) generation raises `ValueError`
that names the field, instead of returning data the target could never accept.
Likewise `generate_invalid()` raises `ValidationRuleNotViolatableError` for
rules that cannot be broken by decodable data (`max_len` equal to the buffer
size, `lte` equal to the type maximum, ...).

## Installation

The generator is part of the nanopb project. Ensure you have the required dependencies:

```bash
pip install protobuf grpcio-tools
```

## Usage

### Command Line Interface

Basic usage:

```bash
# Generate valid data as C array
python generator/nanopb_data_generator.py test_basic_validation.proto BasicValidation

# Generate invalid data violating a specific field
python generator/nanopb_data_generator.py test_basic_validation.proto BasicValidation \
    --invalid --field age --rule lte

# Output as binary file
python generator/nanopb_data_generator.py test_basic_validation.proto BasicValidation \
    --format binary -o valid_data.bin

# Output as hex string
python generator/nanopb_data_generator.py test_basic_validation.proto BasicValidation \
    --format hex

# With custom include paths
python generator/nanopb_data_generator.py my_proto.proto MyMessage \
    -I proto -I third_party/proto
```

#### CLI Options

- `proto_file` - Path to `.proto` file (required)
- `message` - Message name to generate data for (required)
- `--invalid` - Generate invalid data instead of valid
- `--field FIELD` - Field to violate (for invalid data)
- `--rule RULE` - Rule to violate (for invalid data)
- `--format {binary,c_array,hex,dict}` - Output format (default: c_array)
- `--output FILE, -o FILE` - Output file (default: stdout)
- `--seed SEED` - Random seed for reproducibility
- `-I DIR, --include DIR` - Include path for proto files
- `-f FILE, --options-file FILE` - Extra nanopb `.options` file (repeatable);
  `<proto>.options` is always read automatically

### Python API

```python
from nanopb_data_generator import DataGenerator, OutputFormat

# Create generator
generator = DataGenerator('test_basic_validation.proto', 
                         include_paths=['generator/proto'])

# List available messages
messages = generator.get_messages()
print(messages)  # ['BasicValidation']

# Generate valid data
valid_data = generator.generate_valid('BasicValidation', seed=42)
print(valid_data)
# {
#   'age': 75,
#   'score': 50,
#   'username': 'john_doe',
#   'email': 'user@example.com',
#   ...
# }

# Generate invalid data (random violation)
invalid_data = generator.generate_invalid('BasicValidation')

# Generate invalid data (specific violation)
invalid_data = generator.generate_invalid('BasicValidation',
                                         violate_field='age',
                                         violate_rule='lte')
print(invalid_data['age'])  # Will be > 150 (violating the lte constraint)

# Encode to binary protobuf format
binary_data = generator.encode_to_binary('BasicValidation', valid_data)

# Format output
c_array = generator.format_output(binary_data, 
                                 OutputFormat.C_ARRAY, 
                                 'my_test_data')
print(c_array)
# const uint8_t my_test_data[] = {0x08, 0x4b, 0x10, 0x32, ...};
# const size_t my_test_data_size = 142;

hex_string = generator.format_output(binary_data, OutputFormat.HEX_STRING)
print(hex_string)  # 084b1032...
```

## Examples

### Example 1: Generate Test Vectors

```python
from nanopb_data_generator import DataGenerator, OutputFormat

generator = DataGenerator('my_message.proto')

# Generate 10 valid test cases
for i in range(10):
    data = generator.generate_valid('MyMessage', seed=i)
    binary = generator.encode_to_binary('MyMessage', data)
    c_array = generator.format_output(binary, OutputFormat.C_ARRAY, 
                                     f'test_case_{i}')
    print(c_array)
```

### Example 2: Systematic Invalid Data Testing

```python
from nanopb_data_generator import DataGenerator

generator = DataGenerator('test_basic_validation.proto')

# Get all fields with constraints
all_fields = generator.get_all_fields('BasicValidation')

# Generate invalid data for each constraint
for field_name, field_info in all_fields.items():
    for constraint in field_info.constraints:
        print(f"\nTesting violation: {field_name}.{constraint.rule_type}")
        
        invalid_data = generator.generate_invalid(
            'BasicValidation',
            violate_field=field_name,
            violate_rule=constraint.rule_type
        )
        
        binary = generator.encode_to_binary('BasicValidation', invalid_data)
        # Use this data to test your validation logic
        test_validation(binary)  # Your test function
```

### Example 3: Fuzzing Test Data

```python
import random
from nanopb_data_generator import DataGenerator

generator = DataGenerator('my_api.proto')

# Generate 1000 random test cases (mix of valid and invalid)
for i in range(1000):
    if random.random() < 0.7:
        # 70% valid data
        data = generator.generate_valid('ApiRequest', seed=i)
    else:
        # 30% invalid data
        data = generator.generate_invalid('ApiRequest', seed=i)
    
    binary = generator.encode_to_binary('ApiRequest', data)
    # Feed to your API for testing
    test_api_endpoint(binary)
```

## Output Formats

### Binary (`OutputFormat.BINARY`)
Raw protobuf binary data as bytes.

### C Array (`OutputFormat.C_ARRAY`)
```c
const uint8_t test_data[] = {0x08, 0x4b, 0x10, 0x32, 0x18, 0x01};
const size_t test_data_size = 6;
```

### Hex String (`OutputFormat.HEX_STRING`)
```
084b10321801
```

### Python Dict (`OutputFormat.PYTHON_DICT`)
```python
b'\x08K\x102\x18\x01'
```

## Validation Rules Reference

### Example Proto File

```protobuf
syntax = "proto3";

import "validate.proto";

message User {
  // Age between 18-120
  int32 age = 1 [
    (validate.rules).int32.gte = 18,
    (validate.rules).int32.lte = 120
  ];
  
  // Username 3-20 characters
  string username = 2 [
    (validate.rules).string.min_len = 3,
    (validate.rules).string.max_len = 20
  ];
  
  // Email must contain @
  string email = 3 [
    (validate.rules).string.contains = "@",
    (validate.rules).string.min_len = 5
  ];
  
  // Score must be positive
  int32 score = 4 [
    (validate.rules).int32.gt = 0
  ];
  
  // Tags array with 1-10 items
  repeated string tags = 5 [
    (validate.rules).repeated.min_items = 1,
    (validate.rules).repeated.max_items = 10
  ];
}
```

## Architecture

The data generator consists of several components:

1. **ProtoFieldInfo**: Parses field descriptors and validation constraints
2. **DataGenerator**: Main class for generating test data
3. **Value Generators**: Type-specific generators for valid/invalid values
4. **Encoder**: Encodes data to protobuf wire format
5. **Formatters**: Format binary data to various output formats

## Limitations

- `pattern` rules are not supported (the C runtime has no regex engine either)
- Rules inside nested messages are only violated through the top-level fields
  of the message passed to `generate_invalid()`
- Strings are generated from ASCII characters, so `min_len`/`max_len` (bytes)
  and character counts agree

## Testing

`tests/data_generator_stress` is a regression suite that runs in the normal
`cd tests && scons` build. It generates data for a schema that mixes every
rule with nanopb limits (inline and from `.options` files), then

* decodes it with `pb_decode()` and validates it with the generated C
  validator - valid data has to pass, invalid data has to be rejected on the
  field and rule it was generated for - including the messages carried in
  `google.protobuf.Any` fields (`run_vectors.c`);
* re-checks every rule with an independent Python oracle and covers the cases
  C cannot see (`test_generator_semantics.py`).

Run only that suite with `cd tests && scons data_generator_stress`.

## Integration with Nanopb

The generated test data can be used to:

1. **Test encoding/decoding**: Verify your nanopb-generated code correctly handles data
2. **Test validation**: Ensure validation code catches invalid data
3. **Fuzzing**: Feed random data to find edge cases
4. **Documentation**: Generate example data for documentation

Example integration:

```c
#include "test_basic_validation.pb.h"
#include "test_basic_validation_validate.h"
#include <pb_decode.h>

// Generated by nanopb_data_generator.py
const uint8_t invalid_age_data[] = {0x08, 0xff, 0x01, ...};
const size_t invalid_age_data_size = 142;

void test_validation() {
    BasicValidation msg = BasicValidation_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(invalid_age_data, 
                                                  invalid_age_data_size);
    
    // Decode should succeed
    assert(pb_decode(&stream, BasicValidation_fields, &msg));
    
    // But validation should fail
    assert(!pb_validate_BasicValidation(&msg));
}
```

## Contributing

Contributions are welcome! Areas for improvement:

- [x] Support for nested messages, enums, maps, oneofs
- [x] nanopb storage options (`max_size`, `max_count`, `int_size`, ...)
- [ ] Custom validation rules
- [ ] Better error messages
- [ ] Performance optimizations

## License

This module is part of the nanopb project and follows the same license.

## See Also

- [nanopb documentation](https://jpa.kapsi.fi/nanopb/)
- [protoc-gen-validate](https://github.com/bufbuild/protoc-gen-validate)
- [validate.proto spec](https://github.com/bufbuild/protovalidate)
