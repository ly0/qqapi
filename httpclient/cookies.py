import requests.cookies
import http.cookies
import http.cookiejar
import requests
import copy


class MockResponse:
    """Wraps a `httplib.HTTPMessage` to mimic a `urllib.addinfourl`.

    ...what? Basically, expose the parsed HTTP headers from the server response
    the way `cookielib` expects to see them.
    """

    def __init__(self, headers):
        """Make a MockResponse for `cookielib` to read. has different behaviors to httplib.HTTPMessage
        Be aware, tornado.httputil.HTTPHeader

        :param headers: a httplib.HTTPMessage or analogous carrying the headers
        """
        self._headers = copy.deepcopy(headers)

        _get_all = self._headers.get_all

        def mock_get_all(key=None, default=None):
            if not key:
                result = _get_all()
                return result or default

            return [i[1] for i in _get_all() if i[0] == key] or default

        self._headers.get_all = mock_get_all

    def info(self):
        return self._headers

    def getheaders(self, name):
        self._headers.getheaders(name)


def extract_cookies_to_jar(jar, request, response):
    # the _original_response field is the wrapped httplib.HTTPResponse object,
    req = requests.cookies.MockRequest(request)
    # pull out the HTTPMessage with the headers and put it in the mock:
    res = MockResponse(response.headers)
    jar.extract_cookies(res, req)

def cookie_to_dict(cookie):
    cookie_dict = dict()
    C = http.cookies.Cookie(cookie)

    for morsel in C.values():
        cookie_dict[morsel.key] = morsel.value

    return cookie_dict


def dict_to_cookie(cookie_dict):
    attrs = []

    for (key, value) in cookie_dict.items():
        attrs.append("%s=%s" % (key, value))

    return "; ".join(attrs)


def make_cookiejar(cookiejar, request, response):
    """Returns cookie string by tonado AsyncHTTPClient's request and response
    :param cookiejar:
    :type cookiejar: request.cookie.RequestsCookiejar
    :param request: class:tornado.httpclient.HTTPRequest
    :param response: class:tornado.httpclient.HTTPResponse
    """

    if request and request.headers.get("Cookie"):
        request_cookie = request.headers.get("Cookie")
        if type("") != type(request_cookie):
            request_cookie = request_cookie.encode("utf-8")
        cookie_dict = cookie_to_dict(request_cookie)
        requests.cookies.cookiejar_from_dict(cookie_dict, cookiejar)

    for sc in response.headers.get_list("Set-Cookie"):
        C = http.cookies.SimpleCookie(sc)
        for morsel in C.values():
            if morsel['max-age']:
                morsel['max-age'] = float(morsel['max-age'])

            cookie = requests.cookies.morsel_to_cookie(morsel)
            cookiejar.set_cookie(cookie)
    cookie_dict = cookiejar.get_dict(path="/")

    return dict_to_cookie(cookie_dict)
