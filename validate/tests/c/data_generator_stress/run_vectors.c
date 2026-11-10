/* Decode and validate every vector produced by generate_vectors.py.
 *
 * The vectors come from generator/nanopb_data_generator.py.  A generated
 * "valid" vector must decode with pb_decode() and pass the generated validator
 * (also for every message that is carried inside a google.protobuf.Any), and an
 * "invalid" vector must still decode but be rejected on exactly the field and
 * rule it was generated to violate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pb.h"
#include "pb_decode.h"
#include "pb_common.h"
#include "pb_validate.h"

#include "stress.pb.h"
#include "stress_validate.h"
#include "decode_only.pb.h"
#include "legacy.pb.h"
#include "google/protobuf/any.pb.h"

#include "stress_vectors.h"

typedef bool (*validate_fn)(const void *msg, pb_violations_t *viol);

typedef struct
{
    const char *name;
    const char *type_url;
    const pb_msgdesc_t *fields;
    size_t size;
    validate_fn validate;
} type_entry_t;

#define DEFINE_WRAPPER(p, n) \
    static bool validate_##n(const void *msg, pb_violations_t *viol) \
    { return pb_validate_##p##_##n((const p##_##n *)msg, viol); }
STRESS_TYPES(DEFINE_WRAPPER)

#define STRESS_ENTRY(p, n) \
    {#p "." #n, "type.googleapis.com/" #p "." #n, p##_##n##_fields, sizeof(p##_##n), validate_##n},
#define DECODE_ENTRY(p, n) \
    {#p "." #n, "type.googleapis.com/" #p "." #n, p##_##n##_fields, sizeof(p##_##n), NULL},
/* stresscommon.Meta lives in an imported file but can show up inside an Any. */
static const type_entry_t types[] = {
    STRESS_TYPES(STRESS_ENTRY)
    DECODE_TYPES(DECODE_ENTRY)
    DECODE_ENTRY(stresscommon, Meta)
};

#define NUM_TYPES (sizeof(types) / sizeof(types[0]))
#define NUM_VECTORS (sizeof(vectors) / sizeof(vectors[0]))
#define MAX_DEPTH 6

static int failures = 0;

static void fail(const char *vector, const char *fmt, const char *a, const char *b)
{
    printf("FAIL [%s]: ", vector);
    printf(fmt, a, b);
    printf("\n");
    failures++;
}

static const type_entry_t *find_type_by_name(const char *name)
{
    size_t i;
    for (i = 0; i < NUM_TYPES; i++)
        if (strcmp(types[i].name, name) == 0)
            return &types[i];
    return NULL;
}

static const type_entry_t *find_type_by_url(const char *url)
{
    size_t i;
    for (i = 0; i < NUM_TYPES; i++)
        if (strcmp(types[i].type_url, url) == 0)
            return &types[i];
    return NULL;
}

static const char *describe(const pb_violations_t *viol, char *buf, size_t size)
{
    size_t used = 0;
    pb_size_t i, n = pb_violations_count(viol);
    buf[0] = '\0';
    for (i = 0; i < n && used + 80 < size; i++)
        used += (size_t)snprintf(buf + used, size - used, "%s%s@%s", i ? ", " : "",
                                 viol->violations[i].constraint_id ? viol->violations[i].constraint_id : "?",
                                 viol->violations[i].field_path);
    return buf;
}

static bool check_message(const char *vector, const pb_msgdesc_t *desc, const void *msg, int depth);

/* Decode the message carried in an Any and validate it as well. */
static bool check_any(const char *vector, const google_protobuf_Any *any, int depth)
{
    const type_entry_t *type = find_type_by_url(any->type_url);
    pb_violations_t viol;
    char buf[512];
    void *payload;
    bool ok = true;

    if (type == NULL)
    {
        fail(vector, "Any carries unknown type_url '%s'%s", any->type_url, "");
        return false;
    }

    payload = calloc(1, type->size);
    {
        pb_istream_t stream = pb_istream_from_buffer(any->value.bytes, any->value.size);
        if (!pb_decode(&stream, type->fields, payload))
        {
            fail(vector, "Any payload %s does not decode: %s", type->name, PB_GET_ERROR(&stream));
            free(payload);
            return false;
        }
    }

    pb_violations_init(&viol);
    if (type->validate != NULL && !type->validate(payload, &viol))
    {
        fail(vector, "Any payload %s rejected by validator: %s", type->name, describe(&viol, buf, sizeof(buf)));
        ok = false;
    }
    if (depth < MAX_DEPTH && !check_message(vector, type->fields, payload, depth + 1))
        ok = false;

    free(payload);
    return ok;
}

static bool check_sub(const char *vector, const pb_msgdesc_t *desc, const void *msg, int depth)
{
    if (desc == google_protobuf_Any_fields)
        return check_any(vector, (const google_protobuf_Any *)msg, depth);
    return check_message(vector, desc, msg, depth);
}

/* Walk all populated submessages and decode/validate the Any payloads. */
static bool check_message(const char *vector, const pb_msgdesc_t *desc, const void *msg, int depth)
{
    pb_field_iter_t it;
    bool ok = true;

    if (!pb_field_iter_begin(&it, desc, (void *)msg))
        return true;

    do
    {
        pb_size_t count, i;

        if (PB_ATYPE(it.type) != PB_ATYPE_STATIC || PB_LTYPE(it.type) != PB_LTYPE_SUBMESSAGE)
            continue;

        switch (PB_HTYPE(it.type))
        {
            case PB_HTYPE_REQUIRED:
                count = 1;
                break;
            case PB_HTYPE_OPTIONAL:
                count = (it.pSize != NULL && *(bool *)it.pSize) ? 1 : 0;
                break;
            case PB_HTYPE_ONEOF:
                count = (*(pb_size_t *)it.pSize == it.tag) ? 1 : 0;
                break;
            case PB_HTYPE_REPEATED: /* also fixed_count: pSize points to array_size */
                count = *(pb_size_t *)it.pSize;
                break;
            default:
                count = 0;
                break;
        }

        for (i = 0; i < count; i++)
        {
            const char *item = (const char *)it.pData + (size_t)i * it.data_size;
            if (!check_sub(vector, it.submsg_desc, item, depth))
                ok = false;
        }
    } while (pb_field_iter_next(&it));

    return ok;
}

static bool path_matches(const char *path, const char *field)
{
    size_t len = strlen(field);
    return strncmp(path, field, len) == 0 &&
           (path[len] == '\0' || path[len] == '.' || path[len] == '[');
}

static void run_vector(size_t index)
{
    const char *name = vectors[index].name;
    const type_entry_t *type = find_type_by_name(vectors[index].message);
    pb_istream_t stream;
    pb_violations_t viol;
    char buf[1024];
    void *msg;
    bool valid;

    if (type == NULL)
    {
        fail(name, "unknown message type %s%s", vectors[index].message, "");
        return;
    }

    msg = calloc(1, type->size);
    stream = pb_istream_from_buffer(vectors[index].data, vectors[index].size);
    if (!pb_decode(&stream, type->fields, msg))
    {
        /* Data that nanopb cannot store is never a useful test vector. */
        fail(name, "pb_decode failed: %s%s", PB_GET_ERROR(&stream), "");
        free(msg);
        return;
    }

    if (vectors[index].kind == 2)
    {
        /* Decode-only type: the nanopb limits are all that can be verified. */
        check_message(name, type->fields, msg, 0);
        free(msg);
        return;
    }

    pb_violations_init(&viol);
    valid = type->validate(msg, &viol);

    if (vectors[index].kind == 1)
    {
        if (!valid)
            fail(name, "valid data rejected by validator: %s%s", describe(&viol, buf, sizeof(buf)), "");
        else
            check_message(name, type->fields, msg, 0);
    }
    else
    {
        pb_size_t i, n = pb_violations_count(&viol);
        bool found = false;

        if (valid)
        {
            fail(name, "invalid data accepted by validator%s%s", "", "");
        }
        else
        {
            for (i = 0; i < n; i++)
            {
                if (vectors[index].field != NULL &&
                    !path_matches(viol.violations[i].field_path, vectors[index].field))
                {
                    fail(name, "unrelated field rejected (collateral damage): %s%s",
                         describe(&viol, buf, sizeof(buf)), "");
                    found = true;
                    break;
                }
                if (vectors[index].constraint == NULL ||
                    (viol.violations[i].constraint_id != NULL &&
                     strcmp(viol.violations[i].constraint_id, vectors[index].constraint) == 0))
                    found = true;
            }
            if (!found)
                fail(name, "expected constraint %s but got: %s", vectors[index].constraint,
                     describe(&viol, buf, sizeof(buf)));
        }
    }

    free(msg);
}

int main(void)
{
    size_t i;
    int before;

    printf("Running %u generated vectors\n", (unsigned)NUM_VECTORS);
    for (i = 0; i < NUM_VECTORS; i++)
    {
        before = failures;
        run_vector(i);
        (void)before;
    }

    if (failures == 0)
        printf("OK\n");
    else
        printf("%d vector(s) failed\n", failures);
    return failures != 0;
}
