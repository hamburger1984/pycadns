__author__ = 'Andreas Krohn (hamburger1984@gmail.com)'

import pyuv
import pycares
import logging


class pycadns(object):
    """
    >>> loop = pyuv.Loop.default_loop()
    >>> w = pycadns(loop)
    >>> resolved = {}
    >>> def callback(query, result, err):
    ...     if err or not result: return
    ...     if not query in resolved: resolved[query] = sorted(result)
    ...     else: resolved[query].extend(sorted(result))
    >>> w.ptr("8.8.8.8", callback)
    >>> w.queryA('heise.de', callback)
    >>> w.queryAAAA('heise.de')
    >>> w.queryA('time1.google.com', callback)
    >>> w.queryAAAA('time1.google.com')
    >>> loop.run()
    >>> print(sorted(w.results()))
    [('8.8.8.8', ['google-public-dns-a.google.com']), ('heise.de',\
 ['193.99.144.80', '2a02:2e0:3fe:1001:302::']), ('time1.google.com',\
 ['2001:4860:4802:32::f', '216.239.32.15'])]
    """

    # TODO: what about this?
    # Traceback (most recent call last):
    #  File "./src/pycadns.py", line 109, in _poll
    #     self._channel.process_fd(read_fd, write_fd)
    # UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe4 in
    # ..position 14: invalid continuation byte

    ARES_ENODATA = 1
    ARES_EFORMERR = 2
    ARES_ESERVFAIL = 3
    ARES_ENOTFOUND = 4
    ARES_ENOTIMP = 5
    ARES_EREFUSED = 6
    ARES_EBADQUERY = 7
    ARES_EBADNAME = 8
    ARES_EBADFAMILY = 9
    ARES_EBADRESP = 10
    ARES_ECONNREFUSED = 11
    ARES_ETIMEOUT = 12
    ARES_EOF = 13
    ARES_EFILE = 14
    ARES_ENOMEM = 15
    ARES_EDESTRUCTION = 16
    ARES_EBADSTR = 17
    ARES_ECANCELLED = 24

    def __init__(self, loop, timeout=4, tries=2):
        self._channel = pycares.Channel(sock_state_cb=self._sock_state,
                                        timeout=timeout, tries=tries)
        self._fd_map = {}
        self._loop = loop
        self._timer = pyuv.Timer(loop)
        self._queries = []
        self._done = []
        self._results = {}
        self._errors = set()

    def _sock_state(self, fd, readable, writable):
        if readable or writable:
            if fd not in self._fd_map:
                # New socket
                handle = pyuv.Poll(self._loop, fd)
                handle.fd = fd
                self._fd_map[fd] = handle
            else:
                handle = self._fd_map[fd]
            if not self._timer.active:
                self._timer.start(self._timer_tick, 1.0, 1.0)
            handle.start(
                pyuv.UV_READABLE if readable else 0 |
                pyuv.UV_WRITABLE if writable else 0,
                self._poll)
        else:
            handle = self._fd_map.pop(fd)
            handle.close()
            if not self._fd_map:
                self._timer.stop()

    def _timer_tick(self, timer):
        self._channel.process_fd(pycares.ARES_SOCKET_BAD,
                                 pycares.ARES_SOCKET_BAD)

    def _poll(self, handle, events, error):
        try:
            read_fd = handle.fd
            write_fd = handle.fd
            if error is not None:
                self._channel.process_fd(read_fd, write_fd)
                return
            if not events & pyuv.UV_READABLE:
                read_fd = pycares.ARES_SOCKET_BAD
            if not events & pyuv.UV_WRITABLE:
                write_fd = pycares.ARES_SOCKET_BAD
            self._channel.process_fd(read_fd, write_fd)
        except UnicodeDecodeError as ude:
            logging.error('in _poll, %s, %s, %s\n%s',
                          self._queries, self._done, self._results, ude)
            raise

    def ptr(self, ipaddress, callback=None):
        return self._query(pycares.reverse_address(ipaddress), ipaddress,
                           pycares.QUERY_TYPE_PTR, 'PTR%', callback)

    def queryA(self, name, callback=None):
        return self._query(name, name, pycares.QUERY_TYPE_A, 'A%', callback)

    def queryAAAA(self, name, callback=None):
        ## observed errors: [1, 4, 11]
        return self._query(name, name, pycares.QUERY_TYPE_AAAA, 'AAAA%',
                           callback)

    def _query(self, name, originalName, type, queryPrefix, callback=None):
        key = queryPrefix + originalName
        if key in self._done:
            if callback:
                callback(originalName, self._results[originalName], None)
            return
        if key in self._queries:
            return
        self._queries.append(key)

        def context_callback(result, error):
            if not error and result:
                if not originalName in self._results:
                    self._results[originalName] = sorted(result)
                else:
                    self._results[originalName] = sorted(
                        self._results[originalName] + result)
                self._done.append(key)
            self._queries.remove(key)
            if error:
                self._errors.add(error)
            if callback:
                callback(originalName, result, error)

        self._channel.query(name, type, context_callback)

    def results(self, clear=False):
        result = list(self._results.items())
        if clear:
            self._results.clear()
        return result

    def errors(self):
        return self._errors.copy()

if __name__ == '__main__':
    import doctest

    doctest.testmod()
