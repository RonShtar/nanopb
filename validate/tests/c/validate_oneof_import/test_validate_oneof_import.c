/* A oneof arm of a type from another .proto is validated by that file's
 * validator; this only builds if holder_validate.h includes part_validate.h. */

#include <stdio.h>

#include "holder_validate.h"

int main(void)
{
    Holder h = Holder_init_zero;
    int failures = 0;

    h.which_choice = Holder_part_tag;
    h.choice.part.n = 5;
    if (!pb_validate_Holder(&h, NULL)) { printf("FAIL valid arm rejected\n"); failures++; }
    h.choice.part.n = 10;
    if (pb_validate_Holder(&h, NULL)) { printf("FAIL invalid arm accepted\n"); failures++; }

    printf("%s\n", failures ? "FAILED" : "ALL PASSED");
    return failures ? 1 : 0;
}
