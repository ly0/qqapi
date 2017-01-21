import random
from httpclient.session import Session


class QQSession:
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9;'
                      ' rv:27.0) Gecko/20100101 Firefox/27.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }

    def __init__(self):
        self.session = Session(default_headers=self.default_headers)


class Account:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = Session()

    async def login(self):
        await self.session.fetch(
            'https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&'
            'style=16&mibao_css=m_webqq&appid=501004106&enable_qlogin=0&'
            'no_verifyimg=1&s_url=http%3A%2F%2Fw.qq.com%2Fproxy.html&'
            'f_url=loginerroralert&strong_login=1&login_state=10&t=20131024001'
        )

        self.session.cookie_jar.update_cookies({
                                                   'RK': 'OfeLBai4FB',
                                                   'pgv_pvi': '911366144',
                                                   'pgv_info': 'ssid pgv_pvid=1051433466',
                                                   'ptcz': ('ad3bf14f9da2738e09e498bfeb93dd9da7'
                                                            '540dea2b7a71acfb97ed4d3da4e277'),
                                                   'qrsig': ('hJ9GvNx*oIvLjP5I5dQ19KPa3zwxNI'
                                                             '62eALLO*g2JLbKPYsZIRsnbJIxNe74NzQQ')
                                               }.items(), URL('https://ui.ptlogin2.qq.com'))

        print((await self._get_auth_status()).content)
        self.session.cookie_jar._cookies['ssl.ptlogin2.qq.com'].pop('qrsig', None)




    async def _get_auth_status(self):
        return await self.session.get(
            'https://ssl.ptlogin2.qq.com/ptqrlogin?webqq_type=10&' +
            'remember_uin=1&login2qq=1&aid=501004106&u1=http%3A%2F%2F' +
            'w.qq.com%2Fproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&' +
            'ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&' +
            'dumy=&fp=loginerroralert&action=0-0-' +
            repr(random.random() * 900000 + 1000000) +
            '&mibao_css=m_webqq&t=undefined&g=1&js_type=0' +
            '&js_ver=10141&login_sig=&pt_randsalt=0',
            headers={'Referer': 'https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&'
                                'target=self&style=16&mibao_css=m_webqq&appid=501004106&'
                                'enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2F'
                                'w.qq.com%2Fproxy.html&f_url=loginerroralert&'
                                'strong_login=1&login_state=10&t=20131024001'}
        )

