
#include <stdbool.h>
#include <stdio.h>

// Modules
#include "match.h"
#include "blocklist.h"

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid        
// output: output buffer for any redirect URL 
// concurrent: enable handling of "concurrent" requests
// returns: true & redirect URL in output on match, else false
bool match_request(const char* input, char* output, bool concurrent)
{
	// request line elements
	char id[32];
	char url[1024];
	char src_address[256];
	char ident[256];
	char method[32];

	// scan request, ignore if invalid
	if (concurrent) {
		// TODO
		return false;
	}
	else {
		if (sscanf(input, "%1023s %255s %255s %31s", url, src_address, ident, method) < 4) {
			// mangled/invalid input: ignore
			return false;
		}
	}
	
	/// check allow rules first
	if (allow_match(url)) {
		// matched allow rule: return false (no redirect)
		return false;
	}

	// check block rules, return redirect line or empty string
	const char* redirect = block_match(url);
	if (redirect != NULL) {
		// matched block URL: format redirect reply
		if (concurrent) {
			// TODO
			return false;
		}
		else {
			sprintf(output, "%s %s %s %s", redirect, src_address, ident, method);
			return true;
		}
	}

	// No match: pass through
	return false;
}

