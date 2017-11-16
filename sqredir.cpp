
#include <cerrno>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <unistd.h>

#include "blocklist.h"
#include "version.h"

using namespace std;

// must be > length of id+url+src_address+ident+method
static const int REQ_LINE_MAXLENGTH=4096;

// default config file
static const string DEFAULT_CONFIG_FILE = "/etc/sqredir.conf";

// Version
static string version() {
	return string("sqredir ") + SQREDIR_VERSION;
}

// Help
static void usage() {
	cerr << "\n"
		<< version() << "\n"
		<< "\n"
		<< "Usage: sqredir [options]" << "\n"
		<< "\n"
		<< "Options:" << "\n"
		<< "   -f <file>   Specify path to configuration" << "\n"
		<< "   -h          Print this help and exit." << "\n"
		<< "   -v          Print version and exit." << "\n"
		<< "\n";
}


// Magic happens here
int main(int argc, char **argv)
{
	// path of config file
	string config_file = DEFAULT_CONFIG_FILE;

	// parse command line arguments
	int arg = 0;
	while ((arg = getopt(argc, argv, "f:hv")) != -1) {
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
			case 'v': {
				cout << version() << "\n";
				exit(EXIT_SUCCESS);
				break;
			}
			default: {
				usage();
				exit(EXIT_FAILURE);
			}
		}
	}

	try
	{
		// read config file
		blocklist bl(config_file);

		// input buffer for a single request
		char input[REQ_LINE_MAXLENGTH] = {0};

		// loop until EOF from stdin
		while(fgets(input, REQ_LINE_MAXLENGTH-1, stdin) != NULL) {
			bl.match_and_reply(input, stdout);
			fflush(stdout);
		}

		// exit on EOF after 'squid -k reconfigure' or shutdown
	}
	catch (exception& ex) {
		cout << ex.what() << "\n";
		exit(EXIT_FAILURE);
	}
}

