/* pb_validate_<msg>(msg, NULL): pass/fail without collecting violations.
 * Built three times by the SConscript: default, PB_VALIDATE_DEBUG (no early
 * exit) and PB_VALIDATE_EARLY_EXIT=0, where only the failed flag can carry
 * a failure back to the caller. */

#include <stdio.h>
#include <string.h>

#include "without_buffer_validate.h"

static int failures = 0;

#define EXPECT(cond, msg) do { \
    printf("    [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) failures++; \
} while (0)

static void reset(Tree *t)
{
    memset(t, 0, sizeof(*t));
    strcpy(t->name, "t");
    t->has_leaf = true;
    t->leaf.n = 1;
    t->leaves_count = 2;
    t->leaves[0].n = 2;
    t->leaves[1].n = 3;
    t->which_pick = Tree_chosen_tag;
    t->pick.chosen.n = 4;
}

int main(void)
{
    Tree t;
    pb_violations_t violations;

    reset(&t);
    EXPECT(pb_validate_Tree(&t, NULL), "valid tree passes without a buffer");

    reset(&t);
    t.name[0] = '\0';
    EXPECT(!pb_validate_Tree(&t, NULL), "top-level violation fails without a buffer");

    reset(&t);
    t.leaf.n = 10;
    EXPECT(!pb_validate_Tree(&t, NULL), "nested violation fails without a buffer");

    reset(&t);
    t.leaves[1].n = -1;
    EXPECT(!pb_validate_Tree(&t, NULL), "violation in a repeated sub-message fails without a buffer");

    reset(&t);
    t.pick.chosen.n = 99;
    EXPECT(!pb_validate_Tree(&t, NULL), "violation in the selected oneof arm fails without a buffer");

    reset(&t);
    t.which_pick = Tree_code_tag;
    t.pick.code = 4;
    EXPECT(!pb_validate_Tree(&t, NULL), "oneof scalar violation fails without a buffer");

    /* With a buffer the result and the reported path are unchanged. */
    reset(&t);
    t.leaves[1].n = -1;
    pb_violations_init(&violations);
    EXPECT(!pb_validate_Tree(&t, &violations), "same violation fails with a buffer");
    EXPECT(violations.count >= 1 && strcmp(violations.violations[0].field_path, "n") == 0,
           "nested validator reports its own field path");

    printf("%s\n", failures ? "FAILED" : "ALL PASSED");
    return failures ? 1 : 0;
}
