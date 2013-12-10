sqredir
=======

Sqredir is a correct, simple and fast Squid URL rewrite helper based on 
[asqredir](http://asqredir.sourceforge.net/), with bugs removed and
added request batching (what Squid calls 'concurrency').

My primary motivation for this project was adding the request batching;
unfortunately the code was so convoluted that I essentially ended up
refactoring the entire codebase.

More documentation will come in time, but here's a quick HOWTO:

- clone this repo or get a release (>= 0.2)
- make sure you have cmake (http://www.cmake.org/)
- cmake CMakeLists.txt
- make

The cmake configuration step is aware of all the usual cmake flags
and will also be nice to any CC (hello clang!) or custom CFLAGS
you want to specify.

This should give you a binary. Copy it whereever you want it to go,
and copy the template sqredir.conf to /etc (built-in default) or
whereever you want to have it. Alternatively "make install" should
do something reasonably sane as well, even though it's only an initial
cut for now.

Add the following lines to your squid.conf:

    url_rewrite_program /usr/bin/sqredir
    url_rewrite_children 8 startup=4 idle=1 concurrency=8

Note that you want to have the configuration file outside of /etc, you
need to configure the path by adding the -f option to the sqredir executable:

    url_rewrite_program /usr/bin/sqredir -f /where/ever/sqredir.conf

Now add allow/blocklists to your sqredir.conf (it's easy) and kick squid.
Soft-reload works fine; a hard restart is not necessary since soft-reloading
will properly signal & restart all workers.

Enjoy!
