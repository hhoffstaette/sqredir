
#include <regex.h>

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

// reads the given configuration file
// returns: EXIT_SUCCESS or EXIT_FAILURE
int read_config(char *filename);

