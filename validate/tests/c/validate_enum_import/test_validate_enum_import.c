/*
 * enum.defined_only on an enum from an imported file, a local enum and a
 * repeated imported enum: undefined values must be rejected in every case.
 */

#include <stdio.h>

#include "paint_validate.h"

static int tests_failed = 0;

#define EXPECT(cond, msg) do { \
    printf("    [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) tests_failed++; \
} while(0)

static bool check(const x_Paint *paint)
{
    pb_violations_t violations;
    pb_violations_init(&violations);
    return pb_validate_x_Paint(paint, &violations);
}

int main(void)
{
    x_Paint paint = x_Paint_init_zero;

    EXPECT(check(&paint), "defaults are defined values");

    paint.color = (x_Color)7;
    EXPECT(!check(&paint), "undefined imported enum value rejected");
    paint.color = x_Color_GREEN;
    EXPECT(check(&paint), "defined imported enum value accepted");

    paint.local = (x_Local)5;
    EXPECT(!check(&paint), "undefined local enum value rejected");
    paint.local = x_Local_B;

    paint.many_count = 2;
    paint.many[0] = x_Color_RED;
    paint.many[1] = (x_Color)9;
    EXPECT(!check(&paint), "undefined value in repeated imported enum rejected");
    paint.many[1] = x_Color_GREEN;
    EXPECT(check(&paint), "repeated imported enum with defined values accepted");

    return tests_failed ? 1 : 0;
}
