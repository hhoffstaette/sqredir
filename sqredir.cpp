
#include <cerrno>
#include <cstdlib>
#include <iostream>

// getopt
#include <unistd.h>

// Prototypes
#include "blocklist.h"

using namespace std;

// must be > length of id+url+src_address+ident+method
#define REQ_LINE_MAXLENGTH 8192

// default config file
static const string default_config_file = "/etc/sqredir.conf";

// Help
static void usage() {
    cerr << endl
        << "Usage: sqredir [options]" << endl
        << endl
        << "Options:" << endl
        << "   -f <file>   Specify path to blocklist configuration" << endl
        << "   -h          Print this help and exit." << endl
        << endl;
}

// Magic happens here
int main(int argc, char **argv)
{
    // path of config file
    string config_file = default_config_file;

    // parse command line arguments
    int arg = 0;
    while ((arg = getopt(argc, argv, "f:h")) != -1) {
        switch (arg)
        {
            case 'f': {
                config_file = optarg;
                break;
            }
            case 'h': {
                usage();
                exit(EXIT_SUCCESS);
                break;
            }
            default: {
                usage();
                exit(EXIT_FAILURE);
            }
        }
    }

    // read config file
    if (!read_config(config_file)) {
        exit(EXIT_FAILURE);
    }

    // input buffer for a single request
    char input[REQ_LINE_MAXLENGTH] = {0};

    // loop until EOF from stdin
    while(fgets(input, REQ_LINE_MAXLENGTH-1, stdin) != NULL) {
        match_and_reply(input, stdout);
        fflush(stdout);
    }

    // EOF after 'squid -k reconfigure' or shutdown
    exit(EXIT_SUCCESS);
}

