sqredir
=======

Sqredir is a correct, simple and fast Squid URL rewrite helper based on 
[asqredir](http://asqredir.sourceforge.net/), with bugs removed and
added request batching (what Squid calls 'concurrency').

More documentation will come in time, but here's a quick HOWTO:

- clone this repo or get a release (>= 0.2)
- make sure you have cmake (http://www.cmake.org/)
- cmake CMakeLists.txt
- make
- make install should do the right thing as well (initial cut only)

This should give you a binary. Copy it whereever you want it to go,
and copy the template sqredir.conf to /etc (built-in default) or
whereever else you want to have it.

Add the following lines to your squid.conf:

  url_rewrite_program /usr/bin/sqredir
  url_rewrite_children 8 startup=4 idle=1 concurrency=8

Note that you wantot have the config outside of /etc, you need to configure
the path by adding the option -f <config file path> to the sqredir executable.

Now add allow/blocklists to your sqredir.conf and kick squid; reload works
fine, a hard restart is not necessary since soft-reloading will properly
signal & restart all workers.

Enjoy!
