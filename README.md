sqredir
=======

Sqredir is a correct, simple and fast Squid URL rewrite helper based on 
[asqredir](http://asqredir.sourceforge.net/), with bugs removed and
added request batching (what Squid calls 'concurrency').

My primary motivation for this project was to add the request batching
to increase throughput and to reduce per-request latency; unfortunately
the original code was quite convoluted and unmaintained, so I essentially
ended up rewriting the entire codebase.

Main differences are:

- removal of debugging/logging & other duplicated code
- removed unnecessary stdin/stdout buffer configuration
- increased I/O buffers to reduce crashes with long URLs
- used bits of standard C++ for correctness/safety and performance
- use of PCRE to match regexps instead of glibc
  (a noticeable performance improvement)

Here's how to get started:

- clone this repo or get a release (>= 1.0)
- make sure you have cmake (http://www.cmake.org/)
- make sure you have PCRE (http://www.pcre.org/)
  (both runtime and dev packages with POSIX compatibility)
- cmake CMakeLists.txt
- make

The cmake configuration step is aware of all the usual cmake flags
and will also consider any custom CXX (hello clang!) or CXXFLAGS.

The lkast step should give you a single binary called 'sqredir'.
Copy it wherever you want it to go, and copy the template sqredir.conf
to /etc (built-in default location) or anywhere else you want.

Alternatively "make install" should do something reasonably sane
as well; you can also export CMAKE_INSTALL_PREFIX for a custom binary
target path prefix.

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
