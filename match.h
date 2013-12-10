
#include <stdbool.h>

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid
// output: output buffer for any found redirect URL or empty result
void match_request(const char* input, char* output);

