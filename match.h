
// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid
// output: output buffer for any redirect URL
// returns: empty string if unmatched, else redirect URL (in output)
char* match_request(const char* input, char* output);

