
#include <stdbool.h>

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid
// output: response output stream
void match_request(const char* input, FILE* output);

