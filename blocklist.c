
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
    int line;
    struct allow_node* next;
};

// List element for keeping a block pattern and redirect URL */
struct block_node {
    regex_t url;
    char redir[256];
    int line;
    struct block_node* next;
};

// Lists of regexps to block/allow
static struct allow_node* allowlist;
static struct block_node* blocklist;

// match URL against allowlist
bool allow_match(const char* url) {
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
const char* block_match(const char* url) {
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

// append URL pattern to allow list
static bool add_allow_url(const char* pattern, int num)
{
    // TODO: the code path for creating the first and any successor list nodes
    // is unnecessarily duplicated and should be merged.
    if (allowlist == NULL) {
        if ((allowlist = malloc(sizeof(*allowlist))) != NULL) {
            if (regcomp(&allowlist->url, pattern, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
                fprintf(stderr, "regcomp failed for %s\n", pattern);
                return false;
            }
            allowlist->line = num;
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
            allow->line = num;
            allow->next = NULL;
        } else {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return false;
        }
    }

    return true;
}

// append URL pattern and redirect URL to block list 
static bool add_block_url(const char* pattern, const char* redirect, int num)
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
            blocklist->line = num;
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
            block->line = num;
            block->next = NULL;
        } else {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return false;
        }
    }

    return true;
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
            if (!add_allow_url(pattern, i)) {
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
        if (!add_block_url(pattern, redirect, i)) {
            return false;
        }
    }

    fclose(urlfile);
    return true;
}

