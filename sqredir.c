
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Modules
#include "blocklist.h"
#include "match.h"

// default config file
static const char default_config_file[] = "/etc/sqredir.conf";

// I/O buffer size, must be > length of url+src_address+ident+method
#define IOBUFSIZE 4096

// Magic happens here
int main(int argc, char **argv)
{
	// path of config file
	char config_file[1024] = {0};

	// handle command line
	if (argc > 2) {
		fprintf(stderr, "Wrong number of arguments! %s -h for help\n", argv[0]);
		exit(EXIT_FAILURE);
	} else if (argc == 2) {
		if (strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
			fprintf(stderr, "Usage: %s <urlfile>\n", argv[0]);
			exit(EXIT_FAILURE);
		} else {
			strncpy(config_file, argv[1], 1023);
		}
	} else {
		strncpy(config_file, default_config_file, 1023);
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
		bool matched = match_request(input, output);
		fprintf(stdout, "%s\n", matched ? output : "");
		fflush(stdout);
	}

	// EOF after 'squid -k reconfigure' or shutdown
	exit(EXIT_SUCCESS);
}

