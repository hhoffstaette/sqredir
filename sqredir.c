
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// list element for keeping a block pattern and redirect URL */
struct block_node {
	regex_t url;
	char redir[256];
	int line;
	struct block_node* next;
};

// list element for keeping a whitelist URL pattern
struct allow_node {
	regex_t url;
	int line;
	struct allow_node* next;
};

// lists of regexps to block/allow
struct block_node* blocklist;
struct allow_node* allowlist;

// I/O buffer size, must be > length of url+src_address+ident+method
#define IOBUFSIZE 4096

// append url pattern and redirect url to block list 
int add_block_url(char* pattern, char* redirect, int num)
{
	// TODO: the code path for creating the first and successor list nodes
	// is unnecessarily duplicated and should be merged.
	if (blocklist == NULL) {
		if ((blocklist = malloc(sizeof(*blocklist))) != NULL) {
			if (regcomp(&blocklist->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n",pattern);
				return EXIT_FAILURE;
			}
			strcpy(blocklist->redir, redirect);
			blocklist->line = num;
			blocklist->next = NULL;
		} else {
			fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		struct block_node* block = blocklist;
		while (block->next != NULL) {
			block = block->next;
		}
		if ((block->next = malloc(sizeof(*block))) != NULL) {
			block = block->next;
			if (regcomp(&block->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n", pattern);
				return EXIT_FAILURE;
			}
			strcpy(block->redir, redirect);
			block->line = num;
			block->next = NULL;
		} else {
			fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

// append url pattern to allow list
int add_allow_url(char* pattern, int num)
{
	// TODO: the code path for creating the first and any successor list nodes
	// is unnecessarily duplicated and should be merged.
	if (allowlist == NULL) {
		if ((allowlist = malloc(sizeof(*allowlist))) != NULL) {
			if (regcomp(&allowlist->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n", pattern);
				return EXIT_FAILURE;
			}
			allowlist->line = num;
			allowlist->next = NULL;
		} else {
			fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		struct allow_node* allow = allowlist;
		while (allow->next != NULL) {
			allow = allow->next;
		}
		if ((allow->next = malloc(sizeof(*allow))) != NULL) {
			allow = allow->next;
			if (regcomp(&allow->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n", pattern);
				return EXIT_FAILURE;
			}
			allow->line = num;
			allow->next = NULL;
		} else {
			fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

// reads content of config file; recognizes lines starting with '#' as comments
// filename: name of config file including path
void read_config(char *filename)
{
	char comment = '#';
	char pass = '~';
	char pattern[256];
	char redirect[256];
	FILE *urlfile;
	char urlbuffer[1024];

	if ((urlfile = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Unable to open config file %s: %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	for (int i=1; fgets(urlbuffer, 1023, urlfile) != NULL; i++) {
		// ignore empty lines
		if (strlen(urlbuffer) <= 1) {
			continue;
		}

		// ignore comments
		if (urlbuffer[0] == comment) {
			continue;
		}

		// handle pass rules
		if (urlbuffer[0] == pass) {
			if (sscanf(urlbuffer, "%1s%255s", redirect, pattern) != 2) {
				fprintf(stderr, "Invalid format in %s, line %d: %s\n", filename, i, urlbuffer);
				exit(EXIT_FAILURE);
			}

			// call add_allowurl()
			if (add_allow_url(pattern, i) != EXIT_SUCCESS) {
				exit(EXIT_FAILURE);
			}
			continue;
		}

		// must be a deny rule
		if (sscanf(urlbuffer, "%255s %255s", pattern, redirect) != 2) {
			fprintf(stderr, "Invalid format in %s, line %d: %s\n", filename, i, urlbuffer);
			exit(EXIT_FAILURE);
		} 

		// call add_blockurl()
		if (add_block_url(pattern, redirect, i) != EXIT_SUCCESS) {
			exit(EXIT_FAILURE);
		}
	}

	fclose(urlfile);
}

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
	// config file
	static const char default_config_file[] = "/etc/sqredir.conf";
	static char config_file[1024] = {0};

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
	read_config(config_file);

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
