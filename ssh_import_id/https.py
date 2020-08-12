import http.client
import ssl
import urllib.parse
from collections import namedtuple


HttpsResponse = namedtuple('HttpsResponse', ['text', 'status_code', 'headers'])


class HttpHeaders(object):
    """Shim replacement for requests's CaseInsensitiveDict."""

    def __init__(self, headers):
        self._headers = dict((hname.lower(), hval) for hname, hval in headers)

    def get(self, header):
        return self._headers.get(header.lower())


def http_get(url, headers=None, port=None, timeout=15.0):
    """Simple replacement for requests.get."""
    parsed_url = urllib.parse.urlparse(url)

    is_https = (parsed_url.scheme.lower() != 'http')
    if port is None:
        port = 443 if is_https else 80

    host = parsed_url.netloc
    if ':' in host:
        host, port_str = host.rsplit(':', 1)
        port = int(port_str)

    path = parsed_url.path
    if parsed_url.query:
        path = '%s?%s' % (path, parsed_url.query)

    if headers is None:
        headers = {}

    if is_https:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        conn.request('GET', path, headers=headers)
        response = conn.getresponse()
        return HttpsResponse(response.read().decode('utf-8'), response.status, HttpHeaders(response.getheaders()))
    finally:
        conn.close()
