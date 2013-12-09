
#include <stdbool.h>

// enable/disable request concurrency; disabled by default
void set_match_concurrency_enabled(bool enabled);

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid
// output: output buffer for any redirect URL
// returns: true & redirect URL in output on match, else false
bool match_request(const char* input, char* output);

