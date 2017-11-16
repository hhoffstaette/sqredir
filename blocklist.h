
#ifndef SQREDIR_BLOCKLIST_H
#define SQREDIR_BLOCKLIST_H

#include <cstdio>
#include <string>
#include <vector>
#include <pcreposix.h>

// element for keeping a block pattern and redirect URL
struct block_node {
	regex_t url;
	std::string redirect;
};

class blocklist
{
	public:
	// reads the given configuration file
	blocklist(std::string filename);
	~blocklist();

	// tries to match the given Squid request & writes the response to the output stream
	// input: a request line as passed by Squid
	// output: response output stream (usually stdout)
	void match_and_reply(const char* input, FILE* output);

	private:
	// whitelisted URL patterns
	std::vector<regex_t> _allow_list;
	// blacklisted pattern -> redirect URL mappings
	std::vector<struct block_node> _block_list;
};

#endif
