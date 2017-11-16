
#include "blocklist.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;

static string err_regcomp_failed(const char* pattern) {
	return string("Internal error: regcomp() failed for ") + pattern;
}

static string err_fopen_failed(string& filename, int code) {
	return string("Unable to open '") + filename + "': " + strerror(code);
}

static string err_invalid_line_format(string& filename, int line) {
	return string("Invalid format in '") + filename + "', line " + to_string(line);
}

// append URL pattern to allow list
static bool add_allow_url(vector<regex_t>& allow_list, const char* pattern)
{
	regex_t allow;

	if (regcomp(&allow, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
		return false;
	}

	allow_list.push_back(allow);
	return true;
}

// append URL pattern and redirect URL to block list 
static bool add_block_url(vector<struct block_node>& block_list, const char* pattern, const char* redirect)
{
	block_node block;
	block.redirect = redirect;

	if (regcomp(&(block.url), pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
		return false;
	}

	block_list.push_back(block);
	return true;
}

// match URL against allowlist
static bool match_allow(const vector<regex_t>& allow_list, const char* url) {
	for (auto& allow: allow_list) {
		if (regexec(&allow, url, 0, NULL, 0) == 0) {
			// matched allow rule
			return true;
		}
	}

	// no match
	return false;
}

// match URL against blocklist
static const char* match_block(const vector<struct block_node>& block_list, const char* url) {
	for (auto& block: block_list) {
		if (regexec(&(block.url), url, 0, NULL, 0) == 0) {
			// matched block URL: return replacement
			return block.redirect.c_str();
		}
	}

	// no match
	return NULL;
}

// tries to match the Squid request & writes the response to the output stream
// input: a request line as passed by Squid
// output: response output stream (usually stdout)
void blocklist::match_and_reply(const char* input, FILE* output)
{
	// request line elements
	char id[8];
	char url[1024];

	// scan request, ignore if invalid (should never happen)
	if (sscanf(input, "%7s %1023s", id, url) < 2) {
		// mangled/invalid input: ignore
		return;
	}

	/// check allow rules first
	if (!match_allow(_allow_list, url)) {
		// did not match an allow rule: check block rules
		const char* redirect = match_block(_block_list, url);
		if (redirect != NULL) {
			// matched block URL: write redirect reply
			fprintf(output, "%s OK status=302 url=%s\n", id, redirect);
			return;
		}
	}

	// you may pass: only write the request id
	fprintf(output, "%s OK\n", id);
	return;
}

// reads content of config file; recognizes lines starting with '#' as comments
// filename: name of config file including path
blocklist::blocklist(std::string filename)
{
	const char comment = '#';
	const char pass = '~';

	char pattern[256];
	char redirect[256];
	char urlbuffer[1024];

	FILE *urlfile;

	if ((urlfile = fopen(filename.c_str(), "r")) == NULL) {
		throw invalid_argument(err_fopen_failed(filename, errno));
	}

	_allow_list.reserve(128);
	_block_list.reserve(128);

	for (int line=1; fgets(urlbuffer, 1023, urlfile) != NULL; line++) {
		// ignore empty lines
		if (strlen(urlbuffer) <= 1) {
			continue;
		}

		// ignore comments
		if (urlbuffer[0] == comment) {
			continue;
		}

		// handle pass rules
		if (urlbuffer[0] == pass) {
			if (sscanf(urlbuffer, "%1s%255s", redirect, pattern) != 2) {
				throw invalid_argument(err_invalid_line_format(filename, line));
			}

			// create allow regexp
			if (!add_allow_url(_allow_list, pattern)) {
				throw runtime_error(err_regcomp_failed(pattern));
			}

			// skip to next line
			continue;
		}

		// must be a deny rule
		if (sscanf(urlbuffer, "%255s %255s", pattern, redirect) != 2) {
			throw invalid_argument(err_invalid_line_format(filename, line));
		} 

		// create blacklist regexp
		if (!add_block_url(_block_list, pattern, redirect)) {
			throw runtime_error(err_regcomp_failed(pattern));
		}
	}

	fclose(urlfile);
}

blocklist::~blocklist()
{
	for (regex_t& allow: _allow_list) {
		regfree(&allow);
	}

	for (block_node& block: _block_list) {
		regfree(&block.url);
	}
}

