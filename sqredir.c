
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Modules
#include "blocklist.h"

// I/O buffer size, must be > length of n * id+url+src_address+ident+method
#define IOBUFSIZE 65536

// default config file
static const char default_config_file[] = "/etc/sqredir.conf";

// Help
static void usage() {
    fprintf(stderr,
        "\n"
        "Usage: sqredir [options]\n"
        "\n"
        "Options:\n"
        "   -f <file>   Specify path to blocklist configuration\n"
        "   -h          Print this help and exit.\n"
        "\n");
}

// Magic happens here
int main(int argc, char **argv)
{
    // path of config file
    char config_file[1024] = {0};
    strncpy(config_file, default_config_file, 1023);

    // parse command line arguments
    int arg = 0;
    while ((arg = getopt(argc, argv, "f:h")) != -1) {
        switch (arg)
        {
            case 'f': {
                strncpy(config_file, optarg, 1023);
                break;
            }
            case 'h': {
                usage();
                exit(EXIT_SUCCESS);
                break;
            }
            default: {
                usage();
                exit(EXIT_FAILURE);
            }
        }
    }

    // read config file
    if (!read_config(config_file)) {
        exit(EXIT_FAILURE);
    }

    // input buffer
    char input[IOBUFSIZE] = {0};

    // loop until EOF from stdin
    while(fgets(input, IOBUFSIZE, stdin) != NULL) {
        match_and_reply(input, stdout);
        fflush(stdout);
    }

    // EOF after 'squid -k reconfigure' or shutdown
    exit(EXIT_SUCCESS);
}

