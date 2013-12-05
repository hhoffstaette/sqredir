
#include <stdbool.h>
#include <stdio.h>

// Modules
#include "match.h"
#include "blocklist.h"

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid        
// output: output buffer for any redirect URL 
// returns: empty string if unmatched, else redirect URL (in output)
bool match_request(const char* input, char* output)
{
	// request line elements
	char url[1024];
	char src_address[256];
	char ident[256];
	char method[32];

	// scan request, ignore if invalid
	int matched = sscanf(input, "%1023s %255s %255s %31s", url, src_address, ident, method);
	if (matched < 4) {
		// mangled/invalid input: ignore
		return false;
	}

	/// check allow rules first, return empty string if matched
	if (allow_match(url)) {
		// matched allow rule: return
		return false;
	}

	// check block rules, return redirect line or empty string
	const char* redirect = block_match(url);
	if (redirect != NULL) {
		// matched block URL: format reply
		sprintf(output, "%s %s %s %s", redirect, src_address, ident, method);
		return true;
	}

	// No match: pass through
	return false;
}
