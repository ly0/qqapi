import copy
import urllib
from tornado.httpclient import HTTPRequest, HTTPError
from tornado.curl_httpclient import CurlAsyncHTTPClient
from . import cookies
import requests
import requests.cookies
from .log import get_logger
from .cookies import extract_cookies_to_jar
import urllib.parse


class Session:
    
    logger = get_logger('HTTPClient')
    
    def __init__(self, default_headers: dict=None):
        self._req_params = {}
        self.cookiejar = requests.cookies.RequestsCookieJar()
        self.default_headers = default_headers
        self.http_client = CurlAsyncHTTPClient()

    def pre_request(self, req, *args, **kwargs):
        # set cookies
        # 参数中已经提交了cookies
        cookie = cookies.dict_to_cookie(self.cookiejar)
        req.headers.update({'Cookie': cookie})
        for k, v in kwargs.items():
            # I feel I just have ate 5 pieces of shit
            if k.lower() == 'headers':
                req.headers.update(kwargs['headers'])
            else:
                setattr(req, k, v)

        if cookie:
            req.headers.update({'Cookie': cookie})

    def post_request(self, req, resp, *args, **kwargs):
        # merge cookies
        extract_cookies_to_jar(self.cookiejar, req, resp)


    def init_request(self, session, url, **kwargs):
        req = session

        # set default parameters
        session.follow_redirects = False  # 禁止跳转

        # set url
        req.url = url

        # method
        session.method = kwargs.get('method', 'GET')

        if 'data' in kwargs and 'body' in kwargs:
            raise ValueError('parameter "data" and "body" cannot be specify both.')

        # (payload) data
        if 'data' in kwargs:
            if not isinstance(kwargs['data'], dict):
                raise TypeError('Parameter data must be dict')

            encoded_data = dict(
                (k, v if not isinstance(v, str) else v.encode('utf-8')) for k, v in kwargs['data'].items())
            payload = urllib.parse.urlencode(encoded_data)
            session.body = payload
            print(session.body)

        if 'body' in kwargs:
            if isinstance(kwargs['body']) != bytes:
                raise TypeError('body must be bytes, but received %s' % type(kwargs['body']))

            session.body = kwargs['body']

        if session.method == "POST" and not session.body:
            session.body = " "

        # set default header
        if self.default_headers:
            req.headers.update(self.default_headers)
        else:
            req.headers.update({'User-Agent': kwargs.get('user-agent', 'Mozilla/5.0 PyCrawler')})

        # update specified cookies
        if 'cookies' in kwargs:
            if isinstance(kwargs['cookies'], dict):
                raise TypeError('Cookies parameter must be instance of dict')

            for k, v in kwargs['cookies']:
                self.cookiejar[k] = v

        # update headers
        req.headers.update(kwargs.get('headers', {}))

    def _get_HTTPRequest(url, **kwargs):
        return HTTPRequest(url, **kwargs)

    async def post(self, url, **kwargs):
        pass

    async def fetch(self, url, **kwargs):
        # init HTTPRequest

        session = HTTPRequest('', follow_redirects=False)
        instance_parameters = copy.deepcopy(self._req_params)  # 参数

        self.init_request(session, url, **kwargs)

        while True:

            self.pre_request(session, url=url, **kwargs)
            try:
                self.logger.info('{method} {url}'.format(method=session.method, url=session.url))

                response = await self.http_client.fetch(session)
                self.logger.log_green('{code} {url}'.format(code=response.code, url=session.url))
                break
            except HTTPError as httperr:
                # redirects handler
                if httperr.code > 300 and httperr.code < 400:
                    self.logger.warning('{code} {url}'.format(code=httperr.code, url=session.url))
                    self.post_request(session, httperr.response, url, **kwargs)
                    if not kwargs.get('disabled_redirect'):
                        url = httperr.response.headers.get('Location')
                    else:
                        self.logger.debug(httperr)
                        return httperr.response
                else:
                    self.logger.error(httperr)
                    raise httperr

        del instance_parameters
        self.post_request(session, response, url, **kwargs)

        return response
