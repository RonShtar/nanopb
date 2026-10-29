/* Rule constants at INT64_MIN, beyond INT64_MAX and at UINT64_MAX. */
#include <stdio.h>
#include "int64_limits_validate.h"
static int check(Big *b) { pb_violations_t v; pb_violations_init(&v); return pb_validate_Big(b, &v); }
int main(void) {
    Big b = Big_init_zero; int r[6];
    b.d = 5; r[0] = check(&b);                                       /* valid */
    b.a = UINT64_C(18000000000000000001); r[1] = check(&b); b.a = 0;  /* a > lte */
    b.b = INT64_MIN; r[2] = check(&b);                                /* gte INT64_MIN ok */
    b.c_count = 1; b.c[0] = UINT64_C(18446744073709551614); r[3] = check(&b); b.c_count = 0;
    b.d = INT64_MIN; r[4] = check(&b); b.d = 5;
    b.e = UINT64_MAX; r[5] = check(&b);
    printf("%d %d %d %d %d %d\n", r[0], r[1], r[2], r[3], r[4], r[5]);
    return !(r[0] && !r[1] && r[2] && !r[3] && r[4] && !r[5]);
}
