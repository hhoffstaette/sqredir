
#include <stdbool.h>

// reads the given configuration file
// returns: true/false for success/failure
bool read_config(char *filename);

// matches the URL against the whitelist
// returns: true/false for match/no match
bool allow_match(char* url);

// matches the URL against the blocklist
// returns: redirect URL or NULL
char* block_match(char* url);

