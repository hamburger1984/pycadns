from pycadns import pycadns

w = pycadns()
w.ptr('8.8.8.8')
w.queryA('heise.de')
w.queryAAAA('heise.de')
w.queryA('time1.google.com')
w.queryAAAA('time1.google.com')
w.run()
print(sorted(w.results()))

## prints something like:
#[('8.8.8.8', ['google-public-dns-a.google.com']),
# ('heise.de', ['193.99.144.80', '2a02:2e0:3fe:1001:302::']),
# ('time1.google.com', ['2001:4860:4802:32::f', '216.239.32.15'])]
