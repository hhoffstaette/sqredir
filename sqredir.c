
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// Blocklist config
#include "blocklist.h"

// I/O buffer size, must be > length of url+src_address+ident+method
#define IOBUFSIZE 4096

// tests the http request and returns the redirect information if necessary
// line: the original http request as passed by squid
// returns: empty string if unmatched, else redirect URL
char* matchurl(const char* input, char* output)
{
	// request line elements
	char url[1024];
	char src_address[256];
	char ident[256];
	char method[32];

	// scan request, ignore if invalid
	int matched = sscanf(input, "%1023s %255s %255s %31s", url, src_address, ident, method);
	if (matched < 4) {
		// mangled/invalid input: ignore
		return ("");
	}

	/// check allow rules first, return empty string if matched
	struct allow_node* allow = allowlist;
	while (allow != NULL) {
		if (!regexec(&allow->url, url, (size_t) 0, NULL, 0)) {
			// matched allow rule: return
			return("");
		}
		allow = allow->next;
	}

	// check block rules, return redirect line or empty string
	struct block_node* block = blocklist;
	while (block != NULL) {
		if (!regexec(&block->url, url, (size_t) 0, NULL, 0)) {
			// matched block URL: return replacement
			sprintf(output, "%s %s %s %s", block->redir, src_address, ident, method);
			return output;
		}
		block = block->next;
	}

	// No match: pass through
	return("");
}

// Magic happens here
int main(int argc, char **argv)
{
	// default config file
	static const char default_config_file[] = "/etc/sqredir.conf";

	// used config file
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
	int rc = read_config(config_file);
	if (rc != EXIT_SUCCESS) {
		exit(rc);
	}

	// make standard output fully buffered
	char iobuf[IOBUFSIZE] = {0};
	if (setvbuf(stdout, iobuf, _IOFBF, IOBUFSIZE) != 0) {
		fprintf(stderr, "Unable to configure stdout buffer: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// input/output buffers
	char input[IOBUFSIZE];
	char output[IOBUFSIZE];

	// loop until EOF from stdin
	while(fgets(input, IOBUFSIZE, stdin) != NULL) {
		fprintf(stdout, "%s\n", matchurl(input, output));
		fflush(stdout);
	}

	// EOF after 'squid -k reconfigure' or shutdown
	exit(EXIT_SUCCESS);
}
