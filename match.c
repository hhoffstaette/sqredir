
#include <stdbool.h>
#include <stdio.h>

// Modules
#include "match.h"
#include "blocklist.h"

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid        
// output: output buffer for any found redirect URL or empty result
void match_request(const char* input, char* output)
{
    // request line elements
    char id[8];
    char url[1024];
    char src_address[256];
    char ident[256];
    char method[32];

    // scan request, ignore if invalid
    if (sscanf(input, "%7s %1023s %255s %255s %31s", id, url, src_address, ident, method) < 5) {
        // mangled/invalid input: ignore
        sprintf(output, "\n");
        return;
    }
    
    /// check allow rules first
    if (allow_match(url)) {
        // matched allow rule: return
        goto out;
    }

    // check block rules
    const char* redirect = block_match(url);
    if (redirect != NULL) {
        // matched block URL: format redirect reply
        sprintf(output, "%s %s %s %s %s\n", id, redirect, src_address, ident, method);
        return;
    }

out:
    sprintf(output, "%s\n", id);
    return;
}

