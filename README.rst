Usage
-----

This is a simple wrapper around pexpect... Standard usage ::

    from clijockey.lib import CLIMachine
    from clijockey.util import Account

    ## Define a series of username and password pairs here...
    accts = (Account('itsa-mistake', ''), Account('rviews', 'secret2'),)

    ## You can optionally disable auto-enable mode if you like...
    conn = CLIMachine('route-views.routeviews.org', accts,
        auto_priv_mode=False, log_screen=True)

    conn.execute('term len 0')
    conn.execute('show version')

    conn.execute('show users')
    ## Get the result of the 'show users' command...
    user_output = conn.response

    conn.logout()

At this time, only ssh works well; telnet is still somewhat buggy.
