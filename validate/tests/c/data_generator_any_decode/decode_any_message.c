/* Decode a BaseMessage that carries a google.protobuf.Any payload.
 *
 * The encoded data is produced by generator/nanopb_data_generator.py (see
 * generate_data.py), so this test verifies that data generated from the
 * validation rules decodes with pb_decode() and passes the generated
 * validation code, both for the outer message and for the message that was
 * transported inside the Any field.
 */

#include <stdio.h>
#include <string.h>

#include "pb.h"
#include "pb_decode.h"
#include "pb_validate.h"

#include "base_message.pb.h"
#include "base_message_validate.h"

#include "any_decode_data.h"

static int status = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL: %s (line %d)\n", #cond, __LINE__); \
            status = 1; \
        } \
    } while (0)

static bool decode_base_message(const uint8_t *data, size_t size, anydecode_BaseMessage *msg)
{
    pb_istream_t stream = pb_istream_from_buffer(data, size);
    *msg = (anydecode_BaseMessage)anydecode_BaseMessage_init_zero;
    return pb_decode(&stream, anydecode_BaseMessage_fields, msg);
}

static bool decode_any_payload(const google_protobuf_Any *any, anydecode_SensorReading *payload)
{
    pb_istream_t stream = pb_istream_from_buffer(any->value.bytes, any->value.size);
    *payload = (anydecode_SensorReading)anydecode_SensorReading_init_zero;
    return pb_decode(&stream, anydecode_SensorReading_fields, payload);
}

static const char *first_constraint(const pb_violations_t *viol)
{
    if (pb_violations_has_any(viol) && viol->violations[0].constraint_id != NULL)
        return viol->violations[0].constraint_id;
    return "(none)";
}

/* Valid data: outer message, Any type_url and inner payload all check out. */
static void test_valid_message(void)
{
    anydecode_BaseMessage msg;
    anydecode_SensorReading payload;
    pb_violations_t viol;

    printf("Testing valid generated message\n");

    CHECK(decode_base_message(valid_base_message, valid_base_message_size, &msg));

    CHECK(msg.has_header);
    CHECK(strlen(msg.header.message_id) == expected_message_id_size);
    CHECK(memcmp(msg.header.message_id, expected_message_id, expected_message_id_size) == 0);
    CHECK(msg.header.version == expected_version);

    /* The generator must respect the (nanopb) storage limits, otherwise the
     * decode above would already have failed with an overflow. */
    CHECK(strlen(msg.header.origin) == expected_origin_size);
    CHECK(memcmp(msg.header.origin, expected_origin, expected_origin_size) == 0);
    CHECK(expected_origin_size < sizeof(msg.header.origin));
    CHECK(msg.header.tags_count == expected_tags_count);
    CHECK(msg.header.tags_count <= 3);

    CHECK(msg.has_message);
    CHECK(strlen(msg.message.type_url) == expected_type_url_size);
    CHECK(memcmp(msg.message.type_url, expected_type_url, expected_type_url_size) == 0);
    CHECK(msg.message.value.size > 0);

    pb_violations_init(&viol);
    if (!pb_validate_anydecode_BaseMessage(&msg, &viol))
    {
        printf("FAIL: valid BaseMessage rejected: %s (%s)\n",
               first_constraint(&viol), viol.violations[0].field_path);
        status = 1;
    }

    /* Now decode the message that was sent inside the Any field. */
    CHECK(decode_any_payload(&msg.message, &payload));
    CHECK(strlen(payload.sensor_name) == expected_sensor_name_size);
    CHECK(memcmp(payload.sensor_name, expected_sensor_name, expected_sensor_name_size) == 0);
    CHECK(payload.value == expected_sensor_value);

    pb_violations_init(&viol);
    if (!pb_validate_anydecode_SensorReading(&payload, &viol))
    {
        printf("FAIL: valid SensorReading rejected: %s (%s)\n",
               first_constraint(&viol), viol.violations[0].field_path);
        status = 1;
    }
}

/* Generated data violating the any.in rule of the Any field. */
static void test_invalid_any_type(void)
{
    anydecode_BaseMessage msg;
    pb_violations_t viol;

    printf("Testing generated message with disallowed Any type_url\n");

    CHECK(decode_base_message(invalid_any_type_message, invalid_any_type_message_size, &msg));
    CHECK(msg.has_message);

    pb_violations_init(&viol);
    CHECK(!pb_validate_anydecode_BaseMessage(&msg, &viol));
    CHECK(strcmp(first_constraint(&viol), "any.in") == 0);
}

/* Allowed Any type_url, but the transported message is itself invalid. */
static void test_invalid_any_payload(void)
{
    anydecode_BaseMessage msg;
    anydecode_SensorReading payload;
    pb_violations_t viol;

    printf("Testing generated message with invalid Any payload\n");

    CHECK(decode_base_message(invalid_payload_message, invalid_payload_message_size, &msg));
    CHECK(msg.has_message);

    pb_violations_init(&viol);
    CHECK(pb_validate_anydecode_BaseMessage(&msg, &viol));

    CHECK(decode_any_payload(&msg.message, &payload));

    pb_violations_init(&viol);
    CHECK(!pb_validate_anydecode_SensorReading(&payload, &viol));
    CHECK(strcmp(first_constraint(&viol), expected_payload_constraint) == 0);
}

/* Allowed Any type_url, but the transported message breaks string.const. */
static void test_invalid_any_payload_name(void)
{
    anydecode_BaseMessage msg;
    anydecode_SensorReading payload;
    pb_violations_t viol;

    printf("Testing generated message with invalid Any payload name\n");

    CHECK(decode_base_message(invalid_payload_name_message,
                              invalid_payload_name_message_size, &msg));

    pb_violations_init(&viol);
    CHECK(pb_validate_anydecode_BaseMessage(&msg, &viol));

    CHECK(decode_any_payload(&msg.message, &payload));

    pb_violations_init(&viol);
    CHECK(!pb_validate_anydecode_SensorReading(&payload, &viol));
    CHECK(strcmp(first_constraint(&viol), "string.const") == 0);
}

/* The required Any field was omitted by the data generator: pb_decode()
 * succeeds but leaves has_message false, and validation reports "required".
 */
static void test_missing_any(void)
{
    anydecode_BaseMessage msg;
    pb_violations_t viol;

    printf("Testing generated message with omitted Any field\n");

    CHECK(decode_base_message(missing_any_message, missing_any_message_size, &msg));
    CHECK(msg.has_header);
    CHECK(!msg.has_message);

    pb_violations_init(&viol);
    CHECK(!pb_validate_anydecode_BaseMessage(&msg, &viol));
    CHECK(strcmp(first_constraint(&viol), "required") == 0);
}

int main(void)
{
    test_valid_message();
    test_invalid_any_type();
    test_invalid_any_payload();
    test_invalid_any_payload_name();
    test_missing_any();

    if (status == 0)
        printf("OK\n");

    return status;
}
