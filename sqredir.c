
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Modules
#include "blocklist.h"
#include "match.h"

// I/O buffer size, must be > length of n * id+url+src_address+ident+method
#define IOBUFSIZE 32768

// default config file
static const char default_config_file[] = "/etc/sqredir.conf";

// Help
void usage() {
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

	// make standard output fully buffered
	char stdoutbuf[IOBUFSIZE] = {0};
	if (setvbuf(stdout, stdoutbuf, _IOFBF, IOBUFSIZE) != 0) {
		fprintf(stderr, "Unable to configure stdout buffer: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// input/output buffers
	char input[IOBUFSIZE] = {0};
	char output[IOBUFSIZE] = {0};

	// loop until EOF from stdin
	while(fgets(input, IOBUFSIZE, stdin) != NULL) {
		match_request(input, output);
		fprintf(stdout, "%s", output);
		fflush(stdout);
	}

	// EOF after 'squid -k reconfigure' or shutdown
	exit(EXIT_SUCCESS);
}

