
// Prototypes
#include "blocklist.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <pcreposix.h>

using namespace std;

// List element for keeping a block pattern and redirect URL
struct block_node {
    regex_t url;
    string redirect;
};

// List for keeping whitelist URL patterns
static vector<regex_t> allow_list;

// List for keeping block pattern -> redirect URL mappings
static vector<block_node> block_list;

static void err_regcomp_failed(const char* pattern) {
    cerr << "regcomp failed for " << pattern << endl;
}

static void err_fopen_failed(string filename, int code) {
    cerr << "Unable to open " << filename << ": " << strerror(code) << endl;
}

static void err_invalid_line_format(string filename, int line, const char* urlbuffer) {
    cerr << "Invalid format in " << filename << ", line " << line << ": " << urlbuffer << endl;
}

// append URL pattern to allow list
static bool add_allow_url(const char* pattern)
{
    regex_t allow;

    if (regcomp(&allow, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
        err_regcomp_failed(pattern);
        return false;
    }

    allow_list.push_back(allow);
    return true;
}

// append URL pattern and redirect URL to block list 
static bool add_block_url(const char* pattern, const char* redirect)
{
    block_node block;
    block.redirect = redirect;

    if (regcomp(&(block.url), pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
        err_regcomp_failed(pattern);
        return false;
    }

    block_list.push_back(block);
    return true;
}

// match URL against allowlist
static bool match_allow(const char* url) {
    for (int i = 0, num = allow_list.size(); i < num; i++) {
        if (regexec(&(allow_list[i]), url, 0, NULL, 0) == 0) {
            // matched allow rule
            return true;
        }
    }

    // no match
    return false;
}

// match URL against blocklist
static const char* match_block(const char* url) {
    for (int i = 0, num = block_list.size(); i < num; i++) {
        if (regexec(&(block_list[i].url), url, 0, NULL, 0) == 0) {
            // matched block URL: return replacement
            return block_list[i].redirect.c_str();
        }
    }

    // no match
    return NULL;
}

// reads content of config file; recognizes lines starting with '#' as comments
// filename: name of config file including path
// returns: true/false for success/failure
bool read_config(string filename)
{
    const char comment = '#';
    const char pass = '~';

    char pattern[256];
    char redirect[256];
    char urlbuffer[1024];

    FILE *urlfile;

    if ((urlfile = fopen(filename.c_str(), "r")) == NULL) {
        err_fopen_failed(filename, errno);
        return false;
    }

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
                err_invalid_line_format(filename, line, urlbuffer);
                return false;
            }

            // create regexp
            if (!add_allow_url(pattern)) {
                return false;
            }

            // skip to next line
            continue;
        }

        // must be a deny rule
        if (sscanf(urlbuffer, "%255s %255s", pattern, redirect) != 2) {
            err_invalid_line_format(filename, line, urlbuffer);
            return false;
        } 

        // create regexp
        if (!add_block_url(pattern, redirect)) {
            return false;
        }
    }

    fclose(urlfile);
    return true;
}

// tries to match the Squid request & writes the response to the output stream
// input: a request line as passed by Squid
// output: response output stream (usually stdout)
void match_and_reply(const char* input, FILE* output)
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
    if (!match_allow(url)) {
        // did not match an allow rule: check block rules
        const char* redirect = match_block(url);
        if (redirect != NULL) {
            // matched block URL: write redirect reply
            fprintf(output, "%s OK status=302 url=%s\n", id, redirect);
            return;
        }
    }

    // allow match or no blocklist match: only write the request id
    fprintf(output, "%s OK\n", id);
    return;
}
