/* Every element of a repeated field with an items.*.const rule must match it. */

#include <stdio.h>
#include <string.h>

#include "items_const_validate.h"

static int tests_failed = 0;

#define EXPECT(cond, msg) do { \
    printf("    [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) tests_failed++; \
} while(0)

static bool check(const Lists *lists)
{
    pb_violations_t violations;
    pb_violations_init(&violations);
    return pb_validate_Lists(lists, &violations);
}

int main(void)
{
    Lists lists = Lists_init_zero;

    EXPECT(check(&lists), "empty lists are valid");

    lists.s_count = 2;
    strcpy(lists.s[0], "x");
    strcpy(lists.s[1], "x");
    EXPECT(check(&lists), "all strings equal the constant");
    strcpy(lists.s[1], "y");
    EXPECT(!check(&lists), "string item differing from the constant rejected");
    lists.s_count = 1;

    lists.b_count = 1;
    lists.b[0] = false;
    EXPECT(!check(&lists), "bool item differing from the constant rejected");
    lists.b[0] = true;

    lists.n_count = 2;
    lists.n[0] = 7;
    lists.n[1] = 8;
    EXPECT(!check(&lists), "int32 item differing from the constant rejected");
    lists.n[1] = 7;
    EXPECT(check(&lists), "all items match");

    return tests_failed ? 1 : 0;
}
