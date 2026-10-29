/* pb_validate.h: Runtime support for nanopb validation
 *
 * This file provides the public API for validating protobuf messages
 * against declarative constraints defined using custom options.
 */

#ifndef PB_VALIDATE_H_INCLUDED
#define PB_VALIDATE_H_INCLUDED

#include "pb.h"
#include <stdbool.h>
#include <stddef.h>
#include <time.h>  /* For timestamp validation */

#ifdef __cplusplus
extern "C"
{
#endif

/* Configuration options */
#ifndef PB_VALIDATE_MAX_VIOLATIONS
#define PB_VALIDATE_MAX_VIOLATIONS 16
#endif

#ifndef PB_VALIDATE_EARLY_EXIT
#define PB_VALIDATE_EARLY_EXIT 1
#endif

#ifndef PB_VALIDATE_MAX_PATH_LENGTH
#define PB_VALIDATE_MAX_PATH_LENGTH 128
#endif

#ifndef PB_VALIDATE_MAX_MESSAGE_LENGTH
#define PB_VALIDATE_MAX_MESSAGE_LENGTH 256
#endif

    /* Maximum simultaneous field/index nesting depth tracked while validating
     * (e.g. "a.b[2].c" is depth 3). This bounds a small fixed-size stack, not
     * a string buffer -- see pb_validate_context_t below. */
    #ifndef PB_VALIDATE_MAX_PATH_DEPTH
    #define PB_VALIDATE_MAX_PATH_DEPTH 16
    #endif

    /* Violation structure representing a single validation error.
     *
     * field_path and (in PB_VALIDATE_DEBUG builds) message are owned copies,
     * materialized only at the moment a violation is recorded. This keeps
     * them valid for the lifetime of the pb_violations_t regardless of how
     * deep in nested/oneof/repeated validation the failure occurred. */
    typedef struct pb_violation_s
    {
        char field_path[PB_VALIDATE_MAX_PATH_LENGTH]; /* Dotted path to the field, e.g., "user.email" */
        const char *constraint_id; /* Constraint identifier, e.g., "string.max_len" (string literal) */
#ifdef PB_VALIDATE_DEBUG
        char message[PB_VALIDATE_MAX_MESSAGE_LENGTH]; /* Human-readable error message, may include values */
#else
        const char *message;       /* Human-readable error message (string literal) */
#endif
    } pb_violation_t;

    /* Violations collection structure */
    typedef struct pb_violations_s
    {
        pb_violation_t violations[PB_VALIDATE_MAX_VIOLATIONS];
        pb_size_t count; /* Number of violations recorded */
        bool truncated;  /* True if more violations were found than could be stored */
    } pb_violations_t;

    /* Initialize a violations structure */
    void pb_violations_init(pb_violations_t *violations);

    /* Add a violation to the collection. field_path and message are copied
     * (not retained by pointer), so the caller's buffers need not outlive
     * this call. */
    bool pb_violations_add(pb_violations_t *violations,
                           const char *field_path,
                           const char *constraint_id,
                           const char *message);

    /* Get the number of violations */
    static inline pb_size_t pb_violations_count(const pb_violations_t *violations)
    {
        return violations ? violations->count : 0;
    }

    /* Check if there are any violations */
    static inline bool pb_violations_has_any(const pb_violations_t *violations)
    {
        return pb_violations_count(violations) > 0;
    }

    /* One segment of the path currently being validated: either a field name
     * (string literal from generated code) or a repeated-item index. Pushing
     * and popping a segment is an O(1) struct store/decrement -- no string
     * work happens until (and unless) a violation is actually recorded. */
    typedef struct pb_validate_path_seg_s
    {
        const char *field_name; /* non-NULL: field-name segment */
        pb_size_t index;        /* valid iff field_name == NULL: array index segment */
    } pb_validate_path_seg_t;

    /* Validation context structure (internal use) */
    typedef struct pb_validate_context_s
    {
        pb_violations_t *violations;
        pb_validate_path_seg_t path_stack[PB_VALIDATE_MAX_PATH_DEPTH];
        pb_size_t path_depth;
        bool failed; /* a rule failed in this call (set even without a violations buffer) */
    } pb_validate_context_t;

        /* Convenience macros for generated validators
         *
         * These allow the code generator to emit compact, macro-based
         * validation code instead of repeating the same boilerplate in
         * every generated *_validate.c file, similar in spirit to the
         * PB_BIND macros used for field descriptors.
         */

    /* Begin / end of a validate function body.
     * Usage:
     *   bool pb_validate_Foo(const Foo *msg, pb_violations_t *violations)
     *   {
     *       PB_VALIDATE_BEGIN(ctx, Foo, msg, violations);
     *       ... field checks ...
     *       PB_VALIDATE_END(ctx, violations);
     *   }
     */
    /* violations_ptr may be NULL: the validator then only answers pass/fail
     * and skips all path bookkeeping (what the packet filters use). The
     * path stack is not cleared: path_depth says how much of it is valid. */
    #define PB_VALIDATE_BEGIN(ctx_var, MsgType, msg_ptr, violations_ptr) \
        pb_validate_context_t ctx_var;                                   \
        ctx_var.violations = (violations_ptr);                           \
        ctx_var.path_depth = 0;                                          \
        ctx_var.failed = false;                                          \
        if (!(msg_ptr)) return false

    #define PB_VALIDATE_END(ctx_var, violations_ptr) \
        (void)(violations_ptr);                         \
        return !(ctx_var).failed

    /* Per-field context helpers. These wrap push/pop of the field name
     * into the validation context's path stack (only kept when there is a
     * violations buffer to report paths to).
     */
    #define PB_VALIDATE_FIELD_BEGIN(ctx_var, field_name_str)                                           \
        do {                                                                                           \
            if ((ctx_var).violations && !pb_validate_context_push_field(&(ctx_var), (field_name_str))) \
                return false;                                                                          \
        } while (0)

    #define PB_VALIDATE_FIELD_END(ctx_var)                                \
        do {                                                              \
            if ((ctx_var).violations) pb_validate_context_pop_field(&(ctx_var)); \
        } while (0)

    /* Helper for guarding checks behind has_XXX flag for OPTIONAL fields.
     * The generator expands FIELD_RULES_ENUM to the field.rules symbol when
     * it knows the field is optional, so that checks are skipped when the
     * field is unset.
     */
    #define PB_VALIDATE_IF_OPTIONAL(has_flag_expr, CODE) do { \
            if (has_flag_expr) {                              \
                CODE                                          \
            }                                                 \
        } while (0)

    /* Whether a failed check should abort validation immediately.
     * Prod (PB_VALIDATE_DEBUG undefined): compile-time constant, folds away
     * entirely -- this is what makes early-exit "free" in the fast path.
     * Debug: always 0, forcing every check to run so all violations on a
     * message are collected in one call.
     */
    #ifdef PB_VALIDATE_DEBUG
    #define PB_VALIDATE_SHOULD_EXIT(ctx_var) (0)
    #else
    #define PB_VALIDATE_SHOULD_EXIT(ctx_var) (PB_VALIDATE_EARLY_EXIT)
    #endif

    /* Record a violation using the context's current path stack and a
     * static (string-literal) message. This is the single point every
     * check macro below funnels through; behavior (whether the message is
     * copied or stored by pointer) is decided once, in pb_violations_add's
     * implementation, based on PB_VALIDATE_DEBUG. It always marks the
     * call as failed, with or without a violations buffer. */
    #define PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, MESSAGE) \
        pb_violations_record(&(ctx_var), (CONSTRAINT_ID), (MESSAGE))

    /* Generic numeric comparison helper. The generator supplies the
     * concrete C type, validator function and rule enum.
     */
#ifdef PB_VALIDATE_DEBUG
    #define PB_VALIDATE_NUMERIC_GENERIC(ctx_var, msg_ptr, field_name, CTYPE, FUNC, RULE_ENUM, VALUE_EXPR, CONSTRAINT_ID) \
        do {                                                                                                            \
            CTYPE __pb_expected = (CTYPE)(VALUE_EXPR);                                                                  \
            if (!FUNC((msg_ptr)->field_name, &__pb_expected, (RULE_ENUM))) {                                            \
                pb_violations_record_numeric(&(ctx_var), (CONSTRAINT_ID), "Value constraint failed",                    \
                                              (double)((msg_ptr)->field_name), (double)__pb_expected);                  \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                                     \
            }                                                                                                           \
        } while (0)
#else
    #define PB_VALIDATE_NUMERIC_GENERIC(ctx_var, msg_ptr, field_name, CTYPE, FUNC, RULE_ENUM, VALUE_EXPR, CONSTRAINT_ID) \
        do {                                                                                                            \
            CTYPE __pb_expected = (CTYPE)(VALUE_EXPR);                                                                  \
            if (!FUNC((msg_ptr)->field_name, &__pb_expected, (RULE_ENUM))) {                                            \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value constraint failed");                                  \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                                     \
            }                                                                                                           \
        } while (0)
#endif

    /* String length helpers for normal (non-callback) string fields. */
#ifdef PB_VALIDATE_DEBUG
    #define PB_VALIDATE_STR_MIN_LEN(ctx_var, msg_ptr, field_name, MIN_LEN, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            uint32_t __pb_min_len_v = (uint32_t)(MIN_LEN);                                                     \
            pb_size_t __pb_len_v = (pb_size_t)strlen((msg_ptr)->field_name);                                   \
            if (!pb_validate_string((msg_ptr)->field_name, __pb_len_v,                                         \
                                    &__pb_min_len_v, PB_VALIDATE_RULE_MIN_LEN)) {                               \
                pb_violations_record_numeric(&(ctx_var), (CONSTRAINT_ID), "String too short",                  \
                                              (double)__pb_len_v, (double)__pb_min_len_v);                      \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                  \
        } while (0)
#else
    #define PB_VALIDATE_STR_MIN_LEN(ctx_var, msg_ptr, field_name, MIN_LEN, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            uint32_t __pb_min_len_v = (uint32_t)(MIN_LEN);                                                     \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),          \
                                    &__pb_min_len_v, PB_VALIDATE_RULE_MIN_LEN)) {                              \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String too short");                                \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)
#endif

#ifdef PB_VALIDATE_DEBUG
    #define PB_VALIDATE_STR_MAX_LEN(ctx_var, msg_ptr, field_name, MAX_LEN, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            uint32_t __pb_max_len_v = (uint32_t)(MAX_LEN);                                                     \
            pb_size_t __pb_len_v = (pb_size_t)strlen((msg_ptr)->field_name);                                   \
            if (!pb_validate_string((msg_ptr)->field_name, __pb_len_v,                                         \
                                    &__pb_max_len_v, PB_VALIDATE_RULE_MAX_LEN)) {                               \
                pb_violations_record_numeric(&(ctx_var), (CONSTRAINT_ID), "String too long",                   \
                                              (double)__pb_len_v, (double)__pb_max_len_v);                      \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                  \
        } while (0)
#else
    #define PB_VALIDATE_STR_MAX_LEN(ctx_var, msg_ptr, field_name, MAX_LEN, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            uint32_t __pb_max_len_v = (uint32_t)(MAX_LEN);                                                     \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),          \
                                    &__pb_max_len_v, PB_VALIDATE_RULE_MAX_LEN)) {                              \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String too long");                                 \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)
#endif

    /* String pattern helpers for normal (non-callback) string fields. */
    #define PB_VALIDATE_STR_PREFIX(ctx_var, msg_ptr, field_name, PREFIX_STR, CONSTRAINT_ID)                     \
        do {                                                                                                    \
            const char *__pb_prefix = (PREFIX_STR);                                                             \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),           \
                                    __pb_prefix, PB_VALIDATE_RULE_PREFIX)) {                                   \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String must start with specified prefix");         \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                   \
        } while (0)

    #define PB_VALIDATE_STR_SUFFIX(ctx_var, msg_ptr, field_name, SUFFIX_STR, CONSTRAINT_ID)                     \
        do {                                                                                                    \
            const char *__pb_suffix = (SUFFIX_STR);                                                             \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),           \
                                    __pb_suffix, PB_VALIDATE_RULE_SUFFIX)) {                                   \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String must end with specified suffix");           \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                   \
        } while (0)

    #define PB_VALIDATE_STR_CONTAINS(ctx_var, msg_ptr, field_name, NEEDLE_STR, CONSTRAINT_ID)                   \
        do {                                                                                                    \
            const char *__pb_needle = (NEEDLE_STR);                                                             \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),           \
                                    __pb_needle, PB_VALIDATE_RULE_CONTAINS)) {                                 \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String must contain specified substring");         \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                   \
        } while (0)

    /* String const_value helper for normal (non-callback) string fields. */
    #define PB_VALIDATE_STR_CONST(ctx_var, msg_ptr, field_name, CONST_STR, CONSTRAINT_ID)                     \
        do {                                                                                                    \
            const char *__pb_const = (CONST_STR);                                                              \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),           \
                                    __pb_const, PB_VALIDATE_RULE_EQ)) {                                        \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must equal specified constant");             \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                   \
        } while (0)

    /* String format validation helpers for normal (non-callback) string fields.
     * These macros validate email, hostname, IP address, and ASCII format.
     */
    #define PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, RULE_ENUM, CONSTRAINT_ID, ERR_MSG)              \
        do {                                                                                                    \
            if (!pb_validate_string((msg_ptr)->field_name, (pb_size_t)strlen((msg_ptr)->field_name),           \
                                    NULL, (RULE_ENUM))) {                                                       \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, ERR_MSG);                                            \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                   \
        } while (0)

    #define PB_VALIDATE_STR_ASCII(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_ASCII, CONSTRAINT_ID, "String must contain only ASCII characters")

    #define PB_VALIDATE_STR_EMAIL(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_EMAIL, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STR_HOSTNAME(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_HOSTNAME, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STR_IP(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_IP, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STR_IPV4(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_IPV4, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STR_IPV6(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STR_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_IPV6, CONSTRAINT_ID, "String format validation failed")

    /* Generic string validation macro for format rules (email, hostname, ip, etc.)
     * that don't require a parameter value. For callback-based string fields.
     */
    #define PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, RULE_ENUM, CONSTRAINT_ID, ERR_MSG) \
        do {                                                                                                    \
            const char *__pb_s = NULL; pb_size_t __pb_l = 0;                                                    \
            if (pb_read_callback_string(&(msg_ptr)->field_name, &__pb_s, &__pb_l)) {                            \
                if (!pb_validate_string(__pb_s, __pb_l, NULL, (RULE_ENUM))) {                                   \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, ERR_MSG);                                        \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                         \
                }                                                                                               \
            }                                                                                                   \
        } while (0)

    /* Generic string validation macro for length rules (min_len, max_len).
     * For callback-based string fields.
     */
    #define PB_VALIDATE_STRING_CALLBACK_LEN(ctx_var, msg_ptr, field_name, RULE_ENUM, LEN_VALUE, CONSTRAINT_ID, ERR_MSG) \
        do {                                                                                                    \
            const char *__pb_s = NULL; pb_size_t __pb_l = 0;                                                    \
            if (pb_read_callback_string(&(msg_ptr)->field_name, &__pb_s, &__pb_l)) {                            \
                uint32_t __pb_len_v = (uint32_t)(LEN_VALUE);                                                    \
                if (!pb_validate_string(__pb_s, __pb_l, &__pb_len_v, (RULE_ENUM))) {                            \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, ERR_MSG);                                        \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                         \
                }                                                                                               \
            }                                                                                                   \
        } while (0)

    /* Generic string validation macro for pattern rules (prefix, suffix, contains).
     * For callback-based string fields.
     */
    #define PB_VALIDATE_STRING_CALLBACK_PATTERN(ctx_var, msg_ptr, field_name, RULE_ENUM, PATTERN_STR, CONSTRAINT_ID, ERR_MSG) \
        do {                                                                                                    \
            const char *__pb_s = NULL; pb_size_t __pb_l = 0;                                                    \
            if (pb_read_callback_string(&(msg_ptr)->field_name, &__pb_s, &__pb_l)) {                            \
                const char *__pb_pattern = (PATTERN_STR);                                                       \
                if (!pb_validate_string(__pb_s, __pb_l, __pb_pattern, (RULE_ENUM))) {                           \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, ERR_MSG);                                        \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                         \
                }                                                                                               \
            }                                                                                                   \
        } while (0)

    /* Unified generic string macro for any rule type with optional parameter.
     * RULE_DATA_EXPR should be a pointer to rule data or NULL for format rules.
     * For callback-based string fields.
     */
    #define PB_VALIDATE_STRING_GENERIC(ctx_var, msg_ptr, field_name, RULE_ENUM, RULE_DATA_EXPR, CONSTRAINT_ID, ERR_MSG) \
        do {                                                                                                    \
            const char *__pb_s = NULL; pb_size_t __pb_l = 0;                                                    \
            if (pb_read_callback_string(&(msg_ptr)->field_name, &__pb_s, &__pb_l)) {                            \
                if (!pb_validate_string(__pb_s, __pb_l, (RULE_DATA_EXPR), (RULE_ENUM))) {                       \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, ERR_MSG);                                        \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                         \
                }                                                                                               \
            }                                                                                                   \
        } while (0)

    /* Format validation macros for callback-based string fields */
    #define PB_VALIDATE_STRING_EMAIL(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_EMAIL, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STRING_HOSTNAME(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_HOSTNAME, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STRING_IP(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_IP, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STRING_IPV4(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_IPV4, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STRING_IPV6(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_IPV6, CONSTRAINT_ID, "String format validation failed")

    #define PB_VALIDATE_STRING_ASCII(ctx_var, msg_ptr, field_name, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_FORMAT(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_ASCII, CONSTRAINT_ID, "String must contain only ASCII characters")

    /* Length validation macros for callback-based string fields */
    #define PB_VALIDATE_STRING_MIN_LEN(ctx_var, msg_ptr, field_name, MIN_LEN, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_LEN(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_MIN_LEN, MIN_LEN, CONSTRAINT_ID, "String too short")

    #define PB_VALIDATE_STRING_MAX_LEN(ctx_var, msg_ptr, field_name, MAX_LEN, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_LEN(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_MAX_LEN, MAX_LEN, CONSTRAINT_ID, "String too long")

    /* Pattern validation macros for callback-based string fields */
    #define PB_VALIDATE_STRING_PREFIX(ctx_var, msg_ptr, field_name, PREFIX_STR, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_PATTERN(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_PREFIX, PREFIX_STR, CONSTRAINT_ID, "String must start with specified prefix")

    #define PB_VALIDATE_STRING_SUFFIX(ctx_var, msg_ptr, field_name, SUFFIX_STR, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_PATTERN(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_SUFFIX, SUFFIX_STR, CONSTRAINT_ID, "String must end with specified suffix")

    #define PB_VALIDATE_STRING_CONTAINS(ctx_var, msg_ptr, field_name, NEEDLE_STR, CONSTRAINT_ID) \
        PB_VALIDATE_STRING_CALLBACK_PATTERN(ctx_var, msg_ptr, field_name, PB_VALIDATE_RULE_CONTAINS, NEEDLE_STR, CONSTRAINT_ID, "String must contain specified substring")

    /* Repeated field size helpers working on *_count naming convention. */
    #define PB_VALIDATE_MIN_ITEMS(ctx_var, msg_ptr, field_name, MIN_ITEMS, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            if (!pb_validate_min_items((msg_ptr)->field_name##_count, (MIN_ITEMS))) {                          \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Too few items");                                    \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_MAX_ITEMS(ctx_var, msg_ptr, field_name, MAX_ITEMS, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            if (!pb_validate_max_items((msg_ptr)->field_name##_count, (MAX_ITEMS))) {                          \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Too many items");                                  \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    /* Repeated unique validation for scalar types (direct comparison). */
    #define PB_VALIDATE_REPEATED_UNIQUE_SCALAR(ctx_var, msg_ptr, field_name, CONSTRAINT_ID)                     \
        do {                                                                                                   \
            for (pb_size_t __pb_i = 0; __pb_i < (msg_ptr)->field_name##_count; ++__pb_i) {                     \
                for (pb_size_t __pb_j = __pb_i + 1; __pb_j < (msg_ptr)->field_name##_count; ++__pb_j) {        \
                    if ((msg_ptr)->field_name[__pb_i] == (msg_ptr)->field_name[__pb_j]) {                      \
                        PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Repeated field elements must be unique");   \
                        if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                     \
                    }                                                                                          \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Repeated unique validation for string types (strcmp comparison). */
    #define PB_VALIDATE_REPEATED_UNIQUE_STRING(ctx_var, msg_ptr, field_name, CONSTRAINT_ID)                     \
        do {                                                                                                   \
            for (pb_size_t __pb_i = 0; __pb_i < (msg_ptr)->field_name##_count; ++__pb_i) {                     \
                for (pb_size_t __pb_j = __pb_i + 1; __pb_j < (msg_ptr)->field_name##_count; ++__pb_j) {        \
                    if (strcmp((msg_ptr)->field_name[__pb_i], (msg_ptr)->field_name[__pb_j]) == 0) {           \
                        PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Repeated field elements must be unique");   \
                        if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                     \
                    }                                                                                          \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Repeated unique validation for bytes types (memcmp comparison). */
    #define PB_VALIDATE_REPEATED_UNIQUE_BYTES(ctx_var, msg_ptr, field_name, CONSTRAINT_ID)                      \
        do {                                                                                                   \
            for (pb_size_t __pb_i = 0; __pb_i < (msg_ptr)->field_name##_count; ++__pb_i) {                     \
                for (pb_size_t __pb_j = __pb_i + 1; __pb_j < (msg_ptr)->field_name##_count; ++__pb_j) {        \
                    if ((msg_ptr)->field_name[__pb_i].size == (msg_ptr)->field_name[__pb_j].size &&            \
                        memcmp((msg_ptr)->field_name[__pb_i].bytes, (msg_ptr)->field_name[__pb_j].bytes,       \
                               (msg_ptr)->field_name[__pb_i].size) == 0) {                                    \
                        PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Repeated field elements must be unique");   \
                        if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                     \
                    }                                                                                          \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Repeated items string length validation macros. */
    #define PB_VALIDATE_REPEATED_ITEMS_STR_MIN_LEN(ctx_var, msg_ptr, field_name, MIN_LEN, CONSTRAINT_ID)        \
        do {                                                                                                   \
            for (pb_size_t __pb_i = 0; __pb_i < (msg_ptr)->field_name##_count; ++__pb_i) {                     \
                pb_validate_context_push_index(&(ctx_var), __pb_i);                                            \
                uint32_t __pb_min_len_v = (uint32_t)(MIN_LEN);                                                 \
                if (!pb_validate_string((msg_ptr)->field_name[__pb_i],                                         \
                                        (pb_size_t)strlen((msg_ptr)->field_name[__pb_i]),                      \
                                        &__pb_min_len_v, PB_VALIDATE_RULE_MIN_LEN)) {                          \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String too short");                            \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) { pb_validate_context_pop_index(&(ctx_var)); return false; } \
                }                                                                                              \
                pb_validate_context_pop_index(&(ctx_var));                                                     \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_REPEATED_ITEMS_STR_MAX_LEN(ctx_var, msg_ptr, field_name, MAX_LEN, CONSTRAINT_ID)        \
        do {                                                                                                   \
            for (pb_size_t __pb_i = 0; __pb_i < (msg_ptr)->field_name##_count; ++__pb_i) {                     \
                pb_validate_context_push_index(&(ctx_var), __pb_i);                                            \
                uint32_t __pb_max_len_v = (uint32_t)(MAX_LEN);                                                 \
                if (!pb_validate_string((msg_ptr)->field_name[__pb_i],                                         \
                                        (pb_size_t)strlen((msg_ptr)->field_name[__pb_i]),                      \
                                        &__pb_max_len_v, PB_VALIDATE_RULE_MAX_LEN)) {                          \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String too long");                             \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) { pb_validate_context_pop_index(&(ctx_var)); return false; } \
                }                                                                                              \
                pb_validate_context_pop_index(&(ctx_var));                                                     \
            }                                                                                                  \
        } while (0)

    /* Repeated items numeric validation macro. */
    #define PB_VALIDATE_REPEATED_ITEMS_NUMERIC(ctx_var, msg_ptr, field_name, CTYPE, FUNC, RULE_ENUM, VALUE_EXPR, CONSTRAINT_ID) \
        do {                                                                                                   \
            for (pb_size_t __pb_i = 0; __pb_i < (msg_ptr)->field_name##_count; ++__pb_i) {                     \
                pb_validate_context_push_index(&(ctx_var), __pb_i);                                            \
                CTYPE __pb_expected = (CTYPE)(VALUE_EXPR);                                                     \
                if (!FUNC((msg_ptr)->field_name[__pb_i], &__pb_expected, (RULE_ENUM))) {                       \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value constraint failed");                     \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) { pb_validate_context_pop_index(&(ctx_var)); return false; } \
                }                                                                                              \
                pb_validate_context_pop_index(&(ctx_var));                                                     \
            }                                                                                                  \
        } while (0)

    /* Bytes length validation macros. */
    #define PB_VALIDATE_BYTES_MIN_LEN(ctx_var, msg_ptr, field_name, MIN_LEN, CONSTRAINT_ID)                     \
        do {                                                                                                   \
            if ((msg_ptr)->field_name.size < (MIN_LEN)) {                                                      \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Bytes too short");                                  \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_BYTES_MAX_LEN(ctx_var, msg_ptr, field_name, MAX_LEN, CONSTRAINT_ID)                     \
        do {                                                                                                   \
            if ((msg_ptr)->field_name.size > (MAX_LEN)) {                                                      \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Bytes too long");                                   \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    /* Bytes const_value validation macro. The expected value is given as a
     * plain byte array plus its length, so that the generated code does not
     * need to construct a pb_bytes_array_t literal.
     */
    #define PB_VALIDATE_BYTES_CONST(ctx_var, msg_ptr, field_name, EXPECTED_ARR, EXPECTED_SIZE, CONSTRAINT_ID)   \
        do {                                                                                                   \
            if ((msg_ptr)->field_name.size != (pb_size_t)(EXPECTED_SIZE) ||                                    \
                ((EXPECTED_SIZE) > 0 &&                                                                        \
                 memcmp((msg_ptr)->field_name.bytes, (EXPECTED_ARR), (size_t)(EXPECTED_SIZE)) != 0)) {         \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must equal specified constant");             \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    /* Enum defined_only validation macro.
     * values_arr must be an array of valid enum values.
     */
    #define PB_VALIDATE_ENUM_DEFINED_ONLY(ctx_var, msg_ptr, field_name, values_arr, CONSTRAINT_ID)              \
        do {                                                                                                   \
            if (!pb_validate_enum_defined_only((int)(msg_ptr)->field_name, (values_arr),                       \
                    (pb_size_t)(sizeof(values_arr)/sizeof((values_arr)[0])))) {                                \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must be a defined enum value");               \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    /* Nested message validation macros. */
    #define PB_VALIDATE_NESTED_MSG(ctx_var, validate_func, msg_ptr, field_name, violations_ptr)                 \
        do {                                                                                                   \
            bool __pb_ok_nested = validate_func(&(msg_ptr)->field_name, (violations_ptr));                     \
            if (!__pb_ok_nested) (ctx_var).failed = true;                                                    \
            if (!__pb_ok_nested && PB_VALIDATE_SHOULD_EXIT(ctx_var)) {                                          \
                pb_validate_context_pop_field(&(ctx_var));                                                     \
                return false;                                                                                  \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_NESTED_MSG_OPTIONAL(ctx_var, validate_func, msg_ptr, field_name, violations_ptr)        \
        do {                                                                                                   \
            if ((msg_ptr)->has_##field_name) {                                                                 \
                bool __pb_ok_nested = validate_func(&(msg_ptr)->field_name, (violations_ptr));                 \
                if (!__pb_ok_nested) (ctx_var).failed = true;                                                    \
            if (!__pb_ok_nested && PB_VALIDATE_SHOULD_EXIT(ctx_var)) {                                      \
                    pb_validate_context_pop_field(&(ctx_var));                                                 \
                    return false;                                                                              \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Sub-messages in an array: every entry is validated and reported by index.
     * COUNT is the number of valid entries, MEMBER is empty for repeated
     * messages or ".value" to validate the value of map entries.
     */
    #define PB_VALIDATE_NESTED_MSG_ARRAY(ctx_var, validate_func, msg_ptr, field_name, COUNT, MEMBER, violations_ptr) \
        do {                                                                                                   \
            pb_size_t __pb_n = (pb_size_t)(COUNT);                                                             \
            for (pb_size_t __pb_i = 0; __pb_i < __pb_n; ++__pb_i) {                                            \
                pb_validate_context_push_index(&(ctx_var), __pb_i);                                            \
                bool __pb_ok_nested = validate_func(&(msg_ptr)->field_name[__pb_i] MEMBER, (violations_ptr));  \
                pb_validate_context_pop_index(&(ctx_var));                                                     \
                if (!__pb_ok_nested) (ctx_var).failed = true;                                                    \
            if (!__pb_ok_nested && PB_VALIDATE_SHOULD_EXIT(ctx_var)) {                                      \
                    pb_validate_context_pop_field(&(ctx_var));                                                 \
                    return false;                                                                              \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_NESTED_MSG_REPEATED(ctx_var, validate_func, msg_ptr, field_name, violations_ptr)        \
        PB_VALIDATE_NESTED_MSG_ARRAY(ctx_var, validate_func, msg_ptr, field_name,                              \
                                     (msg_ptr)->field_name##_count, , violations_ptr)

    /* Same for fixed_count arrays, which have no _count member. */
    #define PB_VALIDATE_NESTED_MSG_FIXARRAY(ctx_var, validate_func, msg_ptr, field_name, violations_ptr)        \
        PB_VALIDATE_NESTED_MSG_ARRAY(ctx_var, validate_func, msg_ptr, field_name,                              \
                                     sizeof((msg_ptr)->field_name) / sizeof((msg_ptr)->field_name[0]), , violations_ptr)

    /* Message held in a oneof arm: validated only while that arm is selected
     * (the caller is already inside the matching case).
     */
    #define PB_VALIDATE_NESTED_MSG_ONEOF(ctx_var, validate_func, msg_ptr, oneof_name, field_name, violations_ptr) \
        do {                                                                                                   \
            bool __pb_ok_nested = validate_func(&(msg_ptr)->oneof_name.field_name, (violations_ptr));          \
            if (!__pb_ok_nested) (ctx_var).failed = true;                                                    \
            if (!__pb_ok_nested && PB_VALIDATE_SHOULD_EXIT(ctx_var)) {                                          \
                pb_validate_context_pop_field(&(ctx_var));                                                     \
                return false;                                                                                  \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_NESTED_MSG_POINTER(ctx_var, validate_func, msg_ptr, field_name, violations_ptr)         \
        do {                                                                                                   \
            if ((msg_ptr)->field_name) {                                                                       \
                bool __pb_ok_nested = validate_func((msg_ptr)->field_name, (violations_ptr));                  \
                if (!__pb_ok_nested) (ctx_var).failed = true;                                                    \
            if (!__pb_ok_nested && PB_VALIDATE_SHOULD_EXIT(ctx_var)) {                                      \
                    pb_validate_context_pop_field(&(ctx_var));                                                 \
                    return false;                                                                              \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Oneof member validation macros.
     * These operate on oneof member fields accessed via msg->oneof_name.field_name
     */
    #define PB_VALIDATE_ONEOF_NUMERIC(ctx_var, msg_ptr, oneof_name, field_name, CTYPE, FUNC, RULE_ENUM, VALUE_EXPR, CONSTRAINT_ID) \
        do {                                                                                                   \
            CTYPE __pb_expected = (CTYPE)(VALUE_EXPR);                                                         \
            if (!FUNC((msg_ptr)->oneof_name.field_name, &__pb_expected, (RULE_ENUM))) {                        \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value constraint failed");                          \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_MIN_LEN(ctx_var, msg_ptr, oneof_name, field_name, MIN_LEN, CONSTRAINT_ID)     \
        do {                                                                                                   \
            uint32_t __pb_min_len = (MIN_LEN);                                                                 \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    &__pb_min_len, PB_VALIDATE_RULE_MIN_LEN)) {                                                \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String too short");                                \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_MAX_LEN(ctx_var, msg_ptr, oneof_name, field_name, MAX_LEN, CONSTRAINT_ID)     \
        do {                                                                                                   \
            uint32_t __pb_max_len = (MAX_LEN);                                                                 \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    &__pb_max_len, PB_VALIDATE_RULE_MAX_LEN)) {                                                \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String too long");                                 \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_PREFIX(ctx_var, msg_ptr, oneof_name, field_name, PREFIX_STR, CONSTRAINT_ID)   \
        do {                                                                                                   \
            const char *__pb_prefix = (PREFIX_STR);                                                            \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    __pb_prefix, PB_VALIDATE_RULE_PREFIX)) {                                                   \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String must start with specified prefix");          \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_SUFFIX(ctx_var, msg_ptr, oneof_name, field_name, SUFFIX_STR, CONSTRAINT_ID)   \
        do {                                                                                                   \
            const char *__pb_suffix = (SUFFIX_STR);                                                            \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    __pb_suffix, PB_VALIDATE_RULE_SUFFIX)) {                                                   \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String must end with specified suffix");            \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_CONTAINS(ctx_var, msg_ptr, oneof_name, field_name, NEEDLE_STR, CONSTRAINT_ID) \
        do {                                                                                                   \
            const char *__pb_needle = (NEEDLE_STR);                                                            \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    __pb_needle, PB_VALIDATE_RULE_CONTAINS)) {                                                 \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "String must contain specified substring");          \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_FORMAT(ctx_var, msg_ptr, oneof_name, field_name, RULE_ENUM, CONSTRAINT_ID, ERR_MSG) \
        do {                                                                                                   \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    NULL, (RULE_ENUM))) {                                                                      \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, ERR_MSG);                                            \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_BYTES_MIN_LEN(ctx_var, msg_ptr, oneof_name, field_name, MIN_LEN, CONSTRAINT_ID)   \
        do {                                                                                                   \
            if ((msg_ptr)->oneof_name.field_name.size < (MIN_LEN)) {                                           \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Bytes too short");                                  \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_BYTES_MAX_LEN(ctx_var, msg_ptr, oneof_name, field_name, MAX_LEN, CONSTRAINT_ID)   \
        do {                                                                                                   \
            if ((msg_ptr)->oneof_name.field_name.size > (MAX_LEN)) {                                           \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Bytes too long");                                   \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_STR_CONST(ctx_var, msg_ptr, oneof_name, field_name, CONST_STR, CONSTRAINT_ID)     \
        do {                                                                                                   \
            const char *__pb_const = (CONST_STR);                                                              \
            if (!pb_validate_string((msg_ptr)->oneof_name.field_name,                                          \
                    (pb_size_t)strlen((msg_ptr)->oneof_name.field_name),                                       \
                    __pb_const, PB_VALIDATE_RULE_EQ)) {                                                        \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must equal specified constant");             \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_BYTES_CONST(ctx_var, msg_ptr, oneof_name, field_name, EXPECTED_ARR, EXPECTED_SIZE, CONSTRAINT_ID) \
        do {                                                                                                   \
            if ((msg_ptr)->oneof_name.field_name.size != (pb_size_t)(EXPECTED_SIZE) ||                         \
                ((EXPECTED_SIZE) > 0 &&                                                                        \
                 memcmp((msg_ptr)->oneof_name.field_name.bytes, (EXPECTED_ARR),                                \
                        (size_t)(EXPECTED_SIZE)) != 0)) {                                                      \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must equal specified constant");             \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    /* Any field validation macros - these check type_url against allowed/disallowed lists.
     * Note: type_urls is an array of const char*, count is the number of entries.
     */
    #define PB_VALIDATE_ANY_IN(ctx_var, msg_ptr, field_name, type_urls, count, CONSTRAINT_ID)                   \
        do {                                                                                                   \
            if ((msg_ptr)->has_##field_name) {                                                                 \
                const char *__pb_type_url = (const char *)(msg_ptr)->field_name.type_url;                      \
                bool __pb_valid = false;                                                                       \
                for (size_t __pb_i = 0; __pb_i < (count); ++__pb_i) {                                          \
                    if (__pb_type_url && strcmp(__pb_type_url, (type_urls)[__pb_i]) == 0) {                    \
                        __pb_valid = true;                                                                     \
                        break;                                                                                 \
                    }                                                                                          \
                }                                                                                              \
                if (!__pb_valid) {                                                                             \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "type_url not in allowed list");                 \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                        \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ANY_NOT_IN(ctx_var, msg_ptr, field_name, type_urls, count, CONSTRAINT_ID)               \
        do {                                                                                                   \
            if ((msg_ptr)->has_##field_name) {                                                                 \
                const char *__pb_type_url = (const char *)(msg_ptr)->field_name.type_url;                      \
                for (size_t __pb_i = 0; __pb_i < (count); ++__pb_i) {                                          \
                    if (__pb_type_url && strcmp(__pb_type_url, (type_urls)[__pb_i]) == 0) {                    \
                        PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "type_url in disallowed list");              \
                        if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                    \
                        break;                                                                                 \
                    }                                                                                          \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Any held in a oneof arm: the arm being selected implies presence. */
    #define PB_VALIDATE_ONEOF_ANY_IN(ctx_var, msg_ptr, oneof_name, field_name, type_urls, count, CONSTRAINT_ID)  \
        do {                                                                                                   \
            const char *__pb_type_url = (const char *)(msg_ptr)->oneof_name.field_name.type_url;               \
            bool __pb_valid = false;                                                                           \
            for (size_t __pb_i = 0; __pb_i < (count); ++__pb_i) {                                              \
                if (__pb_type_url && strcmp(__pb_type_url, (type_urls)[__pb_i]) == 0) {                        \
                    __pb_valid = true;                                                                         \
                    break;                                                                                     \
                }                                                                                              \
            }                                                                                                  \
            if (!__pb_valid) {                                                                                 \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "type_url not in allowed list");                     \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                            \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_ONEOF_ANY_NOT_IN(ctx_var, msg_ptr, oneof_name, field_name, type_urls, count, CONSTRAINT_ID) \
        do {                                                                                                   \
            const char *__pb_type_url = (const char *)(msg_ptr)->oneof_name.field_name.type_url;               \
            for (size_t __pb_i = 0; __pb_i < (count); ++__pb_i) {                                              \
                if (__pb_type_url && strcmp(__pb_type_url, (type_urls)[__pb_i]) == 0) {                        \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "type_url in disallowed list");                  \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                        \
                    break;                                                                                     \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* Timestamp field validation macros - these check google.protobuf.Timestamp against current time.
     * Note: These require <time.h> and may not work on all embedded platforms.
     */
    #define PB_VALIDATE_TIMESTAMP_GT_NOW(ctx_var, msg_ptr, field_name, CONSTRAINT_ID)                         \
        do {                                                                                                   \
            if ((msg_ptr)->has_##field_name) {                                                                 \
                time_t __pb_now = time(NULL);                                                                  \
                int64_t __pb_now_seconds = (int64_t)__pb_now;                                                  \
                if ((msg_ptr)->field_name.seconds <= __pb_now_seconds) {                                       \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "timestamp must be after current time");         \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                        \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_TIMESTAMP_LT_NOW(ctx_var, msg_ptr, field_name, CONSTRAINT_ID)                         \
        do {                                                                                                   \
            if ((msg_ptr)->has_##field_name) {                                                                 \
                time_t __pb_now = time(NULL);                                                                  \
                int64_t __pb_now_seconds = (int64_t)__pb_now;                                                  \
                if ((msg_ptr)->field_name.seconds >= __pb_now_seconds) {                                       \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "timestamp must be before current time");        \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                        \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    #define PB_VALIDATE_TIMESTAMP_WITHIN(ctx_var, msg_ptr, field_name, seconds_val, CONSTRAINT_ID)            \
        do {                                                                                                   \
            if ((msg_ptr)->has_##field_name) {                                                                 \
                time_t __pb_now = time(NULL);                                                                  \
                int64_t __pb_now_seconds = (int64_t)__pb_now;                                                  \
                int64_t __pb_diff = (msg_ptr)->field_name.seconds - __pb_now_seconds;                          \
                if (__pb_diff < 0) __pb_diff = -__pb_diff;                                                     \
                if (__pb_diff > (seconds_val)) {                                                               \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "timestamp not within specified duration from now"); \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                        \
                }                                                                                              \
            }                                                                                                  \
        } while (0)

    /* String in/not_in validation macros.
     * These check if a string value is in or not in a list of allowed/forbidden values.
     */
    #define PB_VALIDATE_STR_IN(ctx_var, msg_ptr, field_name, values_arr, count, CONSTRAINT_ID)                   \
        do {                                                                                                    \
            bool __pb_valid = false;                                                                            \
            for (size_t __pb_i = 0; __pb_i < (count); ++__pb_i) {                                               \
                if (strcmp((msg_ptr)->field_name, (values_arr)[__pb_i]) == 0) {                                 \
                    __pb_valid = true;                                                                          \
                    break;                                                                                      \
                }                                                                                               \
            }                                                                                                   \
            if (!__pb_valid) {                                                                                  \
                PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must be one of allowed set");                  \
                if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                             \
            }                                                                                                   \
        } while (0)

    #define PB_VALIDATE_STR_NOT_IN(ctx_var, msg_ptr, field_name, values_arr, count, CONSTRAINT_ID)               \
        do {                                                                                                    \
            for (size_t __pb_i = 0; __pb_i < (count); ++__pb_i) {                                               \
                if (strcmp((msg_ptr)->field_name, (values_arr)[__pb_i]) == 0) {                                 \
                    PB_VALIDATE_RECORD(ctx_var, CONSTRAINT_ID, "Value must not be one of forbidden set");        \
                    if (PB_VALIDATE_SHOULD_EXIT(ctx_var)) return false;                                         \
                    break;                                                                                      \
                }                                                                                               \
            }                                                                                                   \
        } while (0)

    /* Oneof switch/case macros for cleaner generated code. */
    #define PB_VALIDATE_ONEOF_BEGIN(ctx_var, msg_ptr, oneof_name)                                                \
        switch ((msg_ptr)->which_##oneof_name) {

    #define PB_VALIDATE_ONEOF_CASE(tag_name)                                                                     \
        case tag_name:

    #define PB_VALIDATE_ONEOF_CASE_END()                                                                         \
            break;

    #define PB_VALIDATE_ONEOF_DEFAULT()                                                                          \
        default:                                                                                                \
            break;

    #define PB_VALIDATE_ONEOF_END()                                                                              \
        }

    /* Debug-only pluggable logging hook for generated packet filters
     * (pkg_Msg_filter_udp/filter_tcp). Default is a no-op; an application
     * may #define this before including generated filter code to route
     * rejected-packet diagnostics to its own logger. Generated filter code
     * only calls this from within "#ifdef PB_VALIDATE_DEBUG" blocks, so it
     * costs nothing when debug mode is off.
     */
    #ifndef PB_VALIDATE_FILTER_LOG
    #define PB_VALIDATE_FILTER_LOG(...) ((void)0)
    #endif

    /* Rule types for internal use */
    typedef enum
    {
        PB_VALIDATE_RULE_REQUIRED,
        PB_VALIDATE_RULE_LT,
        PB_VALIDATE_RULE_LTE,
        PB_VALIDATE_RULE_GT,
        PB_VALIDATE_RULE_GTE,
        PB_VALIDATE_RULE_EQ,
        PB_VALIDATE_RULE_IN,
        PB_VALIDATE_RULE_NOT_IN,
        PB_VALIDATE_RULE_MIN_LEN,
        PB_VALIDATE_RULE_MAX_LEN,
        PB_VALIDATE_RULE_ASCII,
        PB_VALIDATE_RULE_PREFIX,
        PB_VALIDATE_RULE_SUFFIX,
        PB_VALIDATE_RULE_CONTAINS,
        PB_VALIDATE_RULE_EMAIL,
        PB_VALIDATE_RULE_HOSTNAME,
        PB_VALIDATE_RULE_IP,
        PB_VALIDATE_RULE_IPV4,
        PB_VALIDATE_RULE_IPV6,
        PB_VALIDATE_RULE_MIN_ITEMS,
        PB_VALIDATE_RULE_MAX_ITEMS,
        PB_VALIDATE_RULE_UNIQUE,
        PB_VALIDATE_RULE_ENUM_DEFINED,
        PB_VALIDATE_RULE_ONEOF_REQUIRED,
        PB_VALIDATE_RULE_REQUIRES,
        PB_VALIDATE_RULE_MUTEX,
        PB_VALIDATE_RULE_AT_LEAST
    } pb_validate_rule_type_t;

    /* Validation functions for primitive types */
    bool pb_validate_int32(int32_t value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_int64(int64_t value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_uint32(uint32_t value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_uint64(uint64_t value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_float(float value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_double(double value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_bool(bool value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_string(const char *value, pb_size_t length, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_bytes(const pb_bytes_array_t *value, const void *rule_data, pb_validate_rule_type_t rule_type);
    bool pb_validate_enum(int value, const void *rule_data, pb_validate_rule_type_t rule_type);

    /* Bytes pattern / set helpers. Generated code passes the expected bytes as
     * a plain array plus length, so no pb_bytes_array_t literal is needed.
     * rule_type is PB_VALIDATE_RULE_PREFIX, _SUFFIX or _CONTAINS.
     */
    bool pb_validate_bytes_pattern(const pb_byte_t *data, size_t size,
                                   const pb_byte_t *pattern, size_t pattern_size,
                                   pb_validate_rule_type_t rule_type);

    typedef struct pb_validate_bytes_item_s
    {
        const pb_byte_t *data;
        size_t size;
    } pb_validate_bytes_item_t;

    /* True if data[0..size) equals one of the items. */
    bool pb_validate_bytes_in(const pb_byte_t *data, size_t size,
                              const pb_validate_bytes_item_t *items, size_t count);

    /* Convenience helper for enum defined_only validation.
     * Returns true if 'value' is one of the provided enumeration values.
     */
    bool pb_validate_enum_defined_only(int value, const int *values, pb_size_t count);

    /* Helper function for validating string/bytes length during decode.
     * This is used by decode callbacks when the full string/bytes data is not stored.
     * For strings: validates length constraints (min_len, max_len).
     * For bytes: validates length constraints (min_len, max_len).
     * Returns true if the length passes validation, false otherwise.
     */
    bool pb_validate_string_length(pb_size_t length, pb_size_t min_len, pb_size_t max_len);
    bool pb_validate_bytes_length(pb_size_t length, pb_size_t min_len, pb_size_t max_len);

    /* Helper to obtain const char* and length from a pb_callback_t string field for validation.
     * Usage model: The application should set the callback's arg pointer to a buffer that
     * contains a NUL-terminated string after decoding. This helper simply exposes that
     * pointer for validation (no copying). Returns true if a valid pointer was obtained.
     * If the callback is NULL or arg is NULL, returns false (treated as empty / missing).
     */
    struct pb_callback_s; /* forward decl from pb.h */
    bool pb_read_callback_string(const struct pb_callback_s *callback, const char **out_str, pb_size_t *out_len);

    /* Helper functions for validation context path tracking (O(1) push/pop,
     * no string work -- see pb_validate_path_seg_t above). */
    bool pb_validate_context_push_field(pb_validate_context_t *ctx, const char *field_name);
    void pb_validate_context_pop_field(pb_validate_context_t *ctx);
    bool pb_validate_context_push_index(pb_validate_context_t *ctx, pb_size_t index);
    void pb_validate_context_pop_index(pb_validate_context_t *ctx);

    /* Record a violation using the context's current path stack, materializing
     * the dotted/bracketed path string only now (and only if the violation
     * will actually be stored, i.e. PB_VALIDATE_MAX_VIOLATIONS not yet hit).
     * This is what PB_VALIDATE_RECORD expands to; called directly by
     * generator-emitted code that doesn't go through one of the check macros
     * above (e.g. hand-emitted loops for repeated.items / in / not_in rules). */
    void pb_violations_record(pb_validate_context_t *ctx, const char *constraint_id, const char *message);

#ifdef PB_VALIDATE_DEBUG
    /* Debug-only: like pb_violations_record, but formats the actual and
     * expected numeric values into the violation message
     * (e.g. "Value constraint failed (got 5000, expected <= 100)").
     * Only used by the macros/emitters that carry a comparable numeric
     * value (numeric rules, string length rules); everything else still
     * records a plain static message via pb_violations_record. */
    void pb_violations_record_numeric(pb_validate_context_t *ctx, const char *constraint_id,
                                       const char *base_message, double actual, double expected);
#endif

    /* Repeated field count helpers */
    static inline bool pb_validate_min_items(pb_size_t count, pb_size_t min_required)
    {
        return count >= min_required;
    }

    static inline bool pb_validate_max_items(pb_size_t count, pb_size_t max_allowed)
    {
        return count <= max_allowed;
    }

/* Encode/decode hook macros (optional) */
#ifdef PB_VALIDATE_BEFORE_ENCODE
#define pb_validate_encode(stream, msg_type, msg) \
    (pb_validate_##msg_type(msg, NULL) ? pb_encode(stream, msg_type##_fields, msg) : false)
#endif

#ifdef PB_VALIDATE_AFTER_DECODE
#define pb_validate_decode(stream, msg_type, msg) \
    (pb_decode(stream, msg_type##_fields, msg) && pb_validate_##msg_type(msg, NULL))
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PB_VALIDATE_H_INCLUDED */
