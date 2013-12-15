
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>

// Modules
#include "blocklist.h"

// List element for keeping a whitelist URL pattern
struct allow_node {
    regex_t url;
    struct allow_node* next;
};

// List element for keeping a block pattern and redirect URL */
struct block_node {
    regex_t url;
    char redir[256];
    struct block_node* next;
};

// Lists of regexps to block/allow
static struct allow_node* allowlist;
static struct block_node* blocklist;

// append URL pattern to allow list
static bool add_allow_url(const char* pattern)
{
    // TODO: the code path for creating the first and any successor list nodes
    // is unnecessarily duplicated and should be merged.
    if (allowlist == NULL) {
        if ((allowlist = malloc(sizeof(*allowlist))) != NULL) {
            if (regcomp(&allowlist->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
                fprintf(stderr, "regcomp failed for %s\n", pattern);
                return false;
            }
            allowlist->next = NULL;
        } else {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return false;
        }
    } else {
        struct allow_node* allow = allowlist;
        while (allow->next != NULL) {
            allow = allow->next;
        }
        if ((allow->next = malloc(sizeof(*allow))) != NULL) {
            allow = allow->next;
            if (regcomp(&allow->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
                fprintf(stderr, "regcomp failed for %s\n", pattern);
                return false;
            }
            allow->next = NULL;
        } else {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return false;
        }
    }

    return true;
}

// append URL pattern and redirect URL to block list 
static bool add_block_url(const char* pattern, const char* redirect)
{
    // TODO: the code path for creating the first and successor list nodes
    // is unnecessarily duplicated and should be merged.
    if (blocklist == NULL) {
        if ((blocklist = malloc(sizeof(*blocklist))) != NULL) {
            if (regcomp(&blocklist->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
                fprintf(stderr, "regcomp failed for %s\n",pattern);
                return false;
            }
            strcpy(blocklist->redir, redirect);
            blocklist->next = NULL;
        } else {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return false;
        }
    } else {
        struct block_node* block = blocklist;
        while (block->next != NULL) {
            block = block->next;
        }
        if ((block->next = malloc(sizeof(*block))) != NULL) {
            block = block->next;
            if (regcomp(&block->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
                fprintf(stderr, "regcomp failed for %s\n", pattern);
                return false;
            }
            strcpy(block->redir, redirect);
            block->next = NULL;
        } else {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return false;
        }
    }

    return true;
}

// match URL against allowlist
static bool allow_match(const char* url) {
    struct allow_node* allow = allowlist;
    while (allow != NULL) {
        if (regexec(&allow->url, url, (size_t) 0, NULL, 0) == 0) {
            // matched allow rule
            return true;
        }
        allow = allow->next;
    }

    // no match
    return false;
}

// match URL against blocklist
static const char* block_match(const char* url) {
    struct block_node* block = blocklist;
    while (block != NULL) {
        if (!regexec(&block->url, url, (size_t) 0, NULL, 0)) {
            // matched block URL: return replacement
            return block->redir;
        }
        block = block->next;
    }

    // no match
    return NULL;
}

// reads content of config file; recognizes lines starting with '#' as comments
// filename: name of config file including path
// returns: true/false for success/failure
bool read_config(const char* filename)
{
    char comment = '#';
    char pass = '~';
    char pattern[256];
    char redirect[256];
    char urlbuffer[1024];
    FILE *urlfile;

    if ((urlfile = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "Unable to open config file %s: %s\n", filename, strerror(errno));
        return false;
    }
    
    for (int i=1; fgets(urlbuffer, 1023, urlfile) != NULL; i++) {
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
                fprintf(stderr, "Invalid format in %s, line %d: %s\n", filename, i, urlbuffer);
                return false;
            }

            // call add_allowurl()
            if (!add_allow_url(pattern)) {
                return false;
            }
            continue;
        }

        // must be a deny rule
        if (sscanf(urlbuffer, "%255s %255s", pattern, redirect) != 2) {
            fprintf(stderr, "Invalid format in %s, line %d: %s\n", filename, i, urlbuffer);
            return false;
        } 

        // call add_blockurl()
        if (!add_block_url(pattern, redirect)) {
            return false;
        }
    }

    fclose(urlfile);
    return true;
}

// tests the HTTP request and returns the redirect information if necessary
// input: the original request as passed by Squid        
// output: response output stream
void match_and_reply(const char* input, FILE* output)
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
        fprintf(output, "\n");
        return;
    }
    
    /// check allow rules first
    if (allow_match(url)) {
        // matched allow rule: just return
    }
    else {
        // check block rules
        const char* redirect = block_match(url);
        if (redirect != NULL) {
            // matched block URL: format redirect reply
            fprintf(output, "%s %s %s %s %s\n", id, redirect, src_address, ident, method);
            return;
        }
    }

    fprintf(output, "%s\n", id);
    return;
}

