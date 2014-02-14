__author__ = 'Andreas Krohn (andreas.krohn@haw-hamburg.de)'

import logging
import pycares
import select
import traceback


class pycadns(object):
    """
    >>> w = pycadns()
    >>> w.ptr('8.8.8.8')
    >>> w.queryA('heise.de')
    >>> w.queryAAAA('heise.de')
    >>> w.queryA('time1.google.com')
    >>> w.queryAAAA('time1.google.com')
    >>> w.run()
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

    def __init__(self, timeout=4, tries=2):
        self._channel = pycares.Channel(timeout=timeout, tries=tries)
        self._fd_map = {}
        self._queries = []
        self._done = []
        self._results = {}
        self._errors = set()

    def run(self):
        chan = self._channel
        while True:
            try:
                read_fds, write_fds = chan.getsock()
                if not read_fds and not write_fds:
                    break
                timeout = chan.timeout()
                if not timeout:
                    chan.process_fd(pycares.ARES_SOCKET_BAD,
                                    pycares.ARES_SOCKET_BAD)
                    continue
                rlist, wlist, xlist = select.select(read_fds, write_fds, [],
                                                    timeout)
                for fd in rlist:
                    chan.process_fd(fd, pycares.ARES_SOCKET_BAD)
                for fd in wlist:
                    chan.process_fd(pycares.ARES_SOCKET_BAD, fd)
            except:
                logging.error('Failure in pycares.run()\n%s',
                              traceback.format_exc())

    def ptr(self, ipaddress, callback=None):
        self._query(pycares.reverse_address(ipaddress), ipaddress,
                    pycares.QUERY_TYPE_PTR, 'PTR%', callback)

    def ptrs(self, ipaddresses, callback=None):
        for i in ipaddresses:
            self.ptr(i, callback)

    def queryA(self, name, callback=None):
        self._query(name, name, pycares.QUERY_TYPE_A, 'A%', callback)

    def queryAAAA(self, name, callback=None):
        ## observed errors: [1, 4, 11]
        self._query(name, name, pycares.QUERY_TYPE_AAAA, 'AAAA%', callback)

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

    def errors(self, clear=False):
        result = self._errors.copy()
        if clear:
            self._errors.clear()
        return result


if __name__ == '__main__':
    import doctest

    doctest.testmod()
