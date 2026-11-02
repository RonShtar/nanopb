/* Code from `nanopb_generator.py --validate` builds and validates. */

#include <stdio.h>
#include <string.h>

#include <pb_encode.h>
#include "cli_validate.h"

static int tests_failed = 0;

#define EXPECT(cond, msg) do { \
    printf("    [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) tests_failed++; \
} while(0)

static int filter(const Command *cmd)
{
    uint8_t buffer[Command_size];
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
    if (!pb_encode(&stream, Command_fields, cmd))
        return -1;
    return Command_filter_udp(NULL, buffer, stream.bytes_written);
}

int main(void)
{
    Command cmd = Command_init_zero;
    strcpy(cmd.name, "start");
    cmd.arg = 5;
    cmd.limits_count = 1;
    strcpy(cmd.limits[0].key, "cpu");
    cmd.limits[0].value = 3;

    EXPECT(pb_validate_Command(&cmd, NULL), "valid command passes");
    EXPECT(filter(&cmd) == 0, "valid command passes the filter");

    strcpy(cmd.name, "reboot");
    EXPECT(!pb_validate_Command(&cmd, NULL), "name not in the list rejected");
    EXPECT(filter(&cmd) != 0, "filter drops it");
    strcpy(cmd.name, "stop");

    cmd.limits[0].value = 0;
    EXPECT(!pb_validate_Command(&cmd, NULL), "map value not > 0 rejected");
    EXPECT(filter(&cmd) != 0, "filter drops it");

    return tests_failed ? 1 : 0;
}
