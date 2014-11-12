pycadns
=======

a slim wrapper for [pycares](https://crate.io/packages/pycares/) (on [github](https://github.com/saghul/pycares))

basic usage:
```python
from pycadns import PycaDns

w = PycaDns()
w.ptr('8.8.8.8')
w.query_a('heise.de')
w.query_aaaa('heise.de')
w.query_a('time1.google.com')
w.query_aaaa('time1.google.com')
w.run()
print(sorted(w.results()))

## prints something like:
#[('8.8.8.8', ['google-public-dns-a.google.com']),
# ('heise.de', ['193.99.144.80', '2a02:2e0:3fe:1001:302::']),
# ('time1.google.com', ['2001:4860:4802:32::f', '216.239.32.15'])]
```
