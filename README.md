# rscan
WARNING!!!!
This is a work in progress. It does not implement rate limiting. Bad things might happen if you run this code.

rscan is a port scanner, similar to [ZMap](https://github.com/zmap/zmap) or [Masscan](https://github.com/robertdavidgraham/masscan).
Unlike ZMap or Masscan, rscan is designed to operate continuously by reading from stdin. Also, rscan can read arbitrary IPv4/IPv6 : port targets, rather than forcing the user to specify ports ahead of time.
