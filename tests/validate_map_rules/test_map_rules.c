/* map.keys / map.values rules are checked on every entry. */

#include <stdio.h>
#include <string.h>

#include "map_rules_validate.h"

static int tests_failed = 0;

#define EXPECT(cond, msg) do { \
    printf("    [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) tests_failed++; \
} while(0)

static pb_violations_t violations;

static bool check(const Inventory *inv)
{
    pb_violations_init(&violations);
    return pb_validate_Inventory(inv, &violations);
}

static bool first_path_is(const char *path)
{
    return violations.count > 0 && strcmp(violations.violations[0].field_path, path) == 0;
}

static Inventory valid_inventory(void)
{
    Inventory inv = Inventory_init_zero;
    inv.counts_count = 2;
    strcpy(inv.counts[0].key, "k_ab");
    inv.counts[0].value = 0;
    strcpy(inv.counts[1].key, "k_cd");
    inv.counts[1].value = 99;
    inv.colors_count = 1;
    inv.colors[0].key = 5;
    inv.colors[0].value = Color_GREEN;
    inv.names_count = 1;
    inv.names[0].key = 0;
    strcpy(inv.names[0].value, "bb");
    inv.wide_count = 1;
    inv.wide[0].key = -4000000001LL;
    return inv;
}

int main(void)
{
    Inventory inv = Inventory_init_zero;

    EXPECT(check(&inv), "empty maps are valid");

    inv = valid_inventory();
    EXPECT(check(&inv), "every key and value follows its rules");
    EXPECT(pb_validate_Inventory(&inv, NULL), "valid without a violations buffer");

    inv = valid_inventory();
    strcpy(inv.counts[1].key, "x_cd");
    EXPECT(!check(&inv), "string key without the prefix rejected");
    EXPECT(first_path_is("counts[1].key"), "violation path names the entry key");
    EXPECT(!pb_validate_Inventory(&inv, NULL), "rejected without a violations buffer");

    inv = valid_inventory();
    strcpy(inv.counts[0].key, "k_");
    EXPECT(!check(&inv), "string key shorter than min_len rejected");

    inv = valid_inventory();
    inv.counts[0].value = 100;
    EXPECT(!check(&inv), "int32 value outside the range rejected");
    EXPECT(first_path_is("counts[0].value"), "violation path names the entry value");

    inv = valid_inventory();
    inv.counts[1].value = -1;
    EXPECT(!check(&inv), "negative int32 value rejected");

    inv = valid_inventory();
    inv.colors[0].key = 0;
    EXPECT(!check(&inv), "int32 key not greater than 0 rejected");

    inv = valid_inventory();
    inv.colors[0].value = (Color)7;
    EXPECT(!check(&inv), "undefined enum value rejected");

    inv = valid_inventory();
    strcpy(inv.names[0].value, "c");
    EXPECT(!check(&inv), "string value not in the list rejected");

    inv = valid_inventory();
    inv.wide[0].key = -4000000000LL;
    EXPECT(!check(&inv), "int64 key not below the limit rejected");

    inv = valid_inventory();
    inv.counts_count = 4;
    strcpy(inv.counts[2].key, "k_ef");
    strcpy(inv.counts[3].key, "k_gh");
    EXPECT(!check(&inv), "more pairs than max_pairs rejected");

    return tests_failed ? 1 : 0;
}
