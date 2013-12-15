
#include <stdbool.h>

// reads the given configuration file
// returns: true/false for success/failure
bool read_config(const char* filename);

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid
// output: response output stream
void match_and_reply(const char* input, FILE* output);


