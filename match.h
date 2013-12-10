
#include <stdbool.h>

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid
// output: output buffer for any redirect URL
// concurrent: enable handling of "concurrent" requests
// returns: true & redirect URL in output on match, else false
bool match_request(const char* input, char* output, bool concurrent);


