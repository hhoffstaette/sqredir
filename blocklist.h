
#ifndef SQREDIR_BLOCKLIST_H
#define SQREDIR_BLOCKLIST_H

#include <cstdio>
#include <string>

// reads the given configuration file
// returns: true/false for success/failure
bool read_config(std::string filename);

// tries to match the Squid request & writes the response to the output stream
// input: a request line as passed by Squid
// output: response output stream (usually stdout)
void match_and_reply(const char* input, FILE* output);

#endif
