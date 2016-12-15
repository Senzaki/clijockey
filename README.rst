
Usage
-----

This is a simple wrapper around pexpect... Standard usage ::

    from clijockey.lib import CLIMachine
    from clijockey.util import Account

    ## Define a tuple of username and password pairs here...
    ##    The first is an expected failure to illustrate how it works
    accts = (Account('itsa-mistake', ''), Account('rviews', 'secret2'),)

    ## You can optionally disable auto-enable mode if you like...
    conn = CLIMachine('route-views.routeviews.org', accts,
        auto_priv_mode=False, log_screen=True, debug=False, command_timeout=5)

    conn.execute('term len 0', wait=0.5)    # Wait 0.5 seconds after the cmd
    conn.execute('show version')

    conn.execute('show users', timeout=60)  # 'show users' outputs slowly...
    ## Get the result of the 'show users' command...
    user_output = conn.response

    conn.logout()

Installation
------------

Don't be fooled by the low version number, it works pretty well.

Install with pip ::

    pip install -U clijockey

Why
---

*Short answer*: 

Because libraries like this should "just work".

*Longer answer*:

There are several similar Python command / response libraries... some even 
have a battery of vendor-specific plugins.  The obvious question is why I think
another library is required.

1.  The popular Python libraries with vendor-specific CLI drivers are 
pointlessly finicky and sometimes don't even work for all permutations from 
that vendor.  I'm tired of working around quirky libraries.
2.  Many of the existing libraries drive SSH sessions slowly because they use 
pure-python SSH (i.e. paramiko)

Goals
-----

1.  Maximum flexiblity from a single CLI driver... no vendor-specific plugins.
2.  Get the most common authentication prompt sequences right
3.  Try a list of credentials until one works.
4.  Don't assume the credentials *always* grant enable privs mode
5.  Speed
6.  Verbose error messages and debugs.
7.  Support both telnet and ssh
8.  Per-session TOML logging (not implemented yet)
9.  Python3 support (not implemented yet)

Restrictions
------------

clijockey only supports *nix (OpenSSH is required); no Windows support.

Right now, I recommend Python 2.x; Python3 support is forthcoming, but a lower
priority
