
#include <stdbool.h>

// reads the given configuration file
// returns: EXIT_SUCCESS or EXIT_FAILURE
int read_config(char *filename);

// matches the URL against the whitelist
// returns: 0 for match or REG_NOMATCH
bool allow_match(char* url);

// matches the URL against the blocklist
// returns: redirect URL or NULL
char* block_match(char* url);


