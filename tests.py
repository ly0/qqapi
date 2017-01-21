import json
import os
import pickle
import random

import sys
import tempfile

import time

import subprocess
from collections import defaultdict

import requests
import tornado
import tornado.gen
import tornado.httpclient
import tornado.ioloop
from httpclient.session import Session
from httpclient.log import get_logger
from qcontacts import QContacts

random.seed(time.time())

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9;'
                  ' rv:27.0) Gecko/20100101 Firefox/27.0',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
}


def qHash(x, K):
    N = [0] * 4
    for T in range(len(K)):
        N[T % 4] ^= ord(K[T])

    U, V = 'ECOK', [0] * 4
    V[0] = ((x >> 24) & 255) ^ ord(U[0])
    V[1] = ((x >> 16) & 255) ^ ord(U[1])
    V[2] = ((x >> 8) & 255) ^ ord(U[2])
    V[3] = ((x >> 0) & 255) ^ ord(U[3])

    U1 = [0] * 8
    for T in range(8):
        U1[T] = N[T >> 1] if T % 2 == 0 else V[T >> 1]

    N1, V1 = '0123456789ABCDEF', ''
    for aU1 in U1:
        V1 += N1[((aU1 >> 4) & 15)]
        V1 += N1[((aU1 >> 0) & 15)]

    return V1


def bknHash(skey):
    hash_str = 5381
    for i in skey:
        hash_str += (hash_str << 5) + ord(i)
    hash_str = int(hash_str & 2147483647)
    return hash_str


class Account:
    def __init__(self, qq):
        self.qq = qq
        self.session = Session(default_headers=DEFAULT_HEADERS)
        self.logger = get_logger('Account')
        self.msg_id = 5310000
        self.client_id = 53999199

        self.group_data = {}
        self.contact_data = {}
        self.group_member_data = {}

    async def loop(self):

        self.contacts = QContacts()
        # await self.get_buddies(contacts)
        await self.get_groups(self.contacts)
        # await self.get_discusses(contacts)

        print(self.contacts.List('group'))


        #await self.get_admins(318495368)
        #mute_result = await self.mute_group_member(318495368, 17076601, 600)
        #await self.mute_group(318495368, enable=True)

        #print(await self.get_group_members(318495368))
        #print(mute_result)

        while True:
            '''
            [{'poll_type': 'group_message', 'value': {'group_code': 4170064607, 'time': 1485007629, 'msg_id': 40231, 'msg_type': 0, 'from_uin': 4170064607, 'to_uin': 3267641449, 'send_uin': 716694329, 'content': [['font', {'size': 10, 'style': [0, 0, 0], 'color': '000000', 'name': '微软雅黑'}], '懂得可能比你都多']}}]

            '''

            msg_type, uin, send_uin, content = await self.poll()
            if msg_type == 'group':
                member = self.contacts.Get(msg_type, uin)[0].members[send_uin]
                name = member['card'] or member['nick']
                await self.send_message(ctype='group', uin=uin, content="[MSGRECV]" + content, at=name)

    async def login(self):
        await self.qrcode()
        await self.after_qr()

    async def qrcode(self):
        await self.session.fetch(
            'https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&'
            'style=16&mibao_css=m_webqq&appid=501004106&enable_qlogin=0&'
            'no_verifyimg=1&s_url=http%3A%2F%2Fw.qq.com%2Fproxy.html&'
            'f_url=loginerroralert&strong_login=1&login_state=10&t=20131024001'
        )

        await self.session.fetch('https://ssl.ptlogin2.qq.com/ptqrshow?'
                                 'appid=501004106&e=0&l=M&s=5&d=72&v=4&t=' + str(random.random()))
        # Wait for auth

        got_qrcode = False

        while True:
            auth_status = (await self._get_auth_status()).body.decode('utf-8')

            if '二维码未失效' in auth_status:
                self.logger.info('登录 Step2 - 等待二维码扫描及授权')
                if not got_qrcode:
                    qrcode_bytes = (await self.get_qrcode())
                    qrcode_path = tempfile.mktemp()
                    with open(qrcode_path, 'wb') as f:
                        f.write(qrcode_bytes)
                    subprocess.call(['gvfs-open', qrcode_path])
                    print('Saved to', qrcode_path)
                    got_qrcode = True
            elif '二维码认证中' in auth_status:
                self.logger.info('二维码已扫描，等待授权')
            elif '二维码已失效' in auth_status:
                self.logger.warning('二维码已失效, 重新获取二维码')
                got_qrcode = False
                qrcode_bytes = (await self.get_qrcode())
                qrcode_path = tempfile.mktemp()
                with open(qrcode_path, 'wb') as f:
                    f.write(qrcode_bytes)
                print('Saved to', qrcode_path)
                # qrcodeManager.Show(self.getQrcode())
            elif '登录成功' in auth_status:
                self.logger.info('已获授权')
                items = auth_status.split(',')
                self.nick = str(items[-1].split("'")[1])
                self.qq = str(int(self.session.cookiejar['superuin'][1:]))
                self.urlPtwebqq = items[2].strip().strip("'")
                break
            else:
                self.logger.error('获取二维码扫描状态时出错, html="%s"', auth_status)
                sys.exit(1)

            await tornado.gen.sleep(5)

    async def after_qr(self):

        self.logger.info('登录 Step3 - 获取ptwebqq')
        try:
            result = await self.session.fetch(self.urlPtwebqq)
        except tornado.httpclient.HTTPError as e:
            if e.code != 404:
                raise e
        self.ptwebqq = self.session.cookiejar['ptwebqq']

        self.logger.info('登录 Step4 - 获取vfwebqq')
        self.vfwebqq = (await self.smart_request(
            url=('http://s.web2.qq.com/api/getvfwebqq?ptwebqq=%s&'
                 'clientid=%s&psessionid=&t={rand}') %
                (self.ptwebqq, self.client_id),
            Referer=('http://s.web2.qq.com/proxy.html?v=20130916001'
                     '&callback=1&id=1'),
            Origin='http://s.web2.qq.com'
        ))['vfwebqq']

        self.logger.info('登录 Step5 - 获取uin和psessionid')
        result = await self.smart_request(
            url='http://d1.web2.qq.com/channel/login2',
            data={
                'r': json.dumps({
                    'ptwebqq': self.ptwebqq, 'clientid': self.client_id,
                    'psessionid': '', 'status': 'online'
                })
            },
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001'
                     '&callback=1&id=2'),
            Origin='http://d1.web2.qq.com'
        )
        self.uin = result['uin']
        self.psessionid = result['psessionid']
        self.hash = qHash(self.uin, self.ptwebqq)
        self.bkn = bknHash(self.session.cookiejar['skey'])

        # Test
        await self.smart_request(
            url=('http://d1.web2.qq.com/channel/get_online_buddies2?'
                 'vfwebqq=%s&clientid=%s&psessionid=%s&t={rand}') %
                (self.vfwebqq, self.client_id, self.psessionid),
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                     'callback=1&id=2'),
            Origin='http://d1.web2.qq.com',
            repeateOnDeny=0
        )

    async def smart_request(self, url, data=None, headers=None,
                            request_timeout=None, timeoutRetVal=None, repeateOnDeny=2, **kw):
        connection_error_counter, time_out_counter, url_error_counter, denied_counter = 0, 0, 0, 0

        headers = headers or {}
        headers.update(kw)
        while True:
            url = url.format(rand=repr(random.random()))
            html = ''
            errorInfo = ''
            # self.session.headers.update(**kw)

            try:
                if data is None:
                    resp = await self.session.fetch(url, headers=headers)
                else:
                    resp = await self.session.fetch(url, headers=headers, method='POST', data=data)
            except tornado.httpclient.HTTPError as e:
                if e.code == 599:
                    continue
                else:
                    connection_error_counter += 1
                    errorInfo = '网络错误 %s' % e
            else:
                html = resp.body.decode('utf-8')

                if resp.code in (502, 504, 404):
                    await self.session.fetch(
                        ('http://pinghot.qq.com/pingd?dm=w.qq.com.hot&'
                         'url=/&hottag=smartqq.im.polltimeout&hotx=9999&'
                         'hoty=9999&rand=%s') % random.randint(10000, 99999)
                    )
                    if url == 'https://d1.web2.qq.com/channel/poll2':
                        return {'errmsg': ''}
                    time_out_counter += 1
                    errorInfo = '超时'
                else:
                    try:
                        result = json.loads(html)
                    except ValueError:
                        url_error_counter += 1
                        errorInfo = ' URL 地址错误'
                    else:
                        retcode = result.get('retcode',
                                             result.get('errCode',
                                                        result.get('ec', -1)))
                        if retcode in (0, 1202, 100003, 100100):
                            return result.get('result', result)
                        else:
                            print(result)
                            denied_counter += 1
                            errorInfo = '请求被拒绝错误'


            self.logger.error(errorInfo)
            # 出现网络错误、超时、 URL 地址错误可以多试几次
            # 若网络没有问题但 retcode 有误，一般连续 3 次都出错就没必要再试了
            if connection_error_counter < 5 and time_out_counter < 20 and url_error_counter < 5 and denied_counter <= repeateOnDeny:
                self.logger.debug('第%d次请求“%s”时出现“%s”, html=%s',
                                  connection_error_counter + time_out_counter + url_error_counter + denied_counter, url,
                                  errorInfo, repr(html))
                time.sleep(0.5)
            elif time_out_counter == 20 and timeoutRetVal:  # by @killerhack
                return timeoutRetVal
            else:
                self.logger.error('第%d次请求“%s”时出现“%s”，终止 QQBot',
                                  connection_error_counter + time_out_counter + url_error_counter + denied_counter, url,
                                  errorInfo)
                raise Exception('QQ Session ERROR')

    async def get_qrcode(self):
        self.logger.info('登录 Step1 - 获取二维码')
        result = await self.session.fetch(
            'https://ssl.ptlogin2.qq.com/ptqrshow?appid=501004106&e=0&l=M&' +
            's=5&d=72&v=4&t=' + repr(random.random())
        )

        return result.body

    async def _get_auth_status(self):

        return await self.session.fetch(
            'https://ssl.ptlogin2.qq.com/ptqrlogin?webqq_type=10&' +
            'remember_uin=1&login2qq=1&aid=501004106&u1=http%3A%2F%2F' +
            'w.qq.com%2Fproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&' +
            'ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&' +
            'dumy=&fp=loginerroralert&action=0-0-' +
            repr(int(random.random() * 900000 + 1000000)) +
            '&mibao_css=m_webqq&t=undefined&g=1&js_type=0' +
            '&js_ver=10141&login_sig=&pt_randsalt=0',
            headers={'Referer': 'https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&'
                                'target=self&style=16&mibao_css=m_webqq&appid=501004106&'
                                'enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2F'
                                'w.qq.com%2Fproxy.html&f_url=loginerroralert&'
                                'strong_login=1&login_state=10&t=20131024001'}
        )

    async def get_buddies_qq(self, uin):
        return (await self.smart_request(
            url=('http://s.web2.qq.com/api/get_friend_uin2?tuin=%s&'
                 'type=1&vfwebqq=%s&t={rand}') % (uin, self.vfwebqq),
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                     'callback=1&id=2'),
            timeoutRetVal={'account': ''}
        ))['account']

    async def get_buddies(self, contacts, silence=False):
        if not silence:
            self.logger.info('登录 Step6 - 获取好友列表')

        result = await self.smart_request(
            url='http://s.web2.qq.com/api/get_user_friends2',
            data={
                'r': json.dumps({'vfwebqq': self.vfwebqq, 'hash': self.hash})
            },
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                     'callback=1&id=2')
        )

        mark_dict = dict((d['uin'], d['markname']) for d in result['marknames'])

        qq_result = await self.smart_request(
            url='http://qun.qq.com/cgi-bin/qun_mgr/get_friend_list',
            data={'bkn': self.bkn},
            Referer='http://qun.qq.com/member.html'
        )
        qq_dict = defaultdict(list)
        for blist in qq_result.values():
            for d in blist.get('mems', []):
                name = d['name'].replace('&nbsp;', ' ').replace('&amp;', '&')
                qq_dict[name].append(d['uin'])

        for info in result['info']:
            uin = info['uin']
            nick = info['nick']
            mark = mark_dict.get(uin, '')
            name = mark or nick
            qqlist = qq_dict.get(name, [])
            if len(qqlist) == 1:
                qq = qqlist.pop()
            else:
                qq = await self.get_buddies_qq(uin)
                try:
                    qqlist.remove(qq)
                except ValueError:
                    pass

            contact = contacts.Add(
                'buddy', str(uin), name, str(qq), nick, mark
            )

            if not silence:
                self.logger.info(repr(contact))

        if not silence:
            self.logger.info('获取朋友列表成功，共 %d 个朋友' % len(result['info']))

    async def get_groups(self, contacts, silence=False):
        if not silence:
            self.logger.info('登录 Step7 - 获取群列表')

        result = await self.smart_request(
            url='http://s.web2.qq.com/api/get_group_name_list_mask2',
            data={
                'r': json.dumps({'vfwebqq': self.vfwebqq, 'hash': self.hash})
            },
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                     'callback=1&id=2')
        )

        print({'vfwebqq': self.vfwebqq, 'hash': self.hash})

        mark_dict = dict((d['uin'], d['markname']) for d in result['gmarklist'])

        qq_result = await self.smart_request(
            url='http://qun.qq.com/cgi-bin/qun_mgr/get_group_list',
            data={'bkn': self.bkn},
            Referer='http://qun.qq.com/member.html'
        )

        qq_dict = defaultdict(list)

        for k in ('create', 'manage', 'join'):
            for d in qq_result.get(k, []):
                name = d['gn'].replace('&nbsp;', ' ').replace('&amp;', '&')
                qq_dict[name].append(d['gc'])

        for info in result['gnamelist']:
            uin = info['gid']
            name = info['name']
            mark = mark_dict.get(uin, '')

            qqlist = qq_dict.get(name, [])
            if len(qqlist) == 1:
                qq = qqlist.pop()
            else:
                qq = self.get_group_qq(uin)
                for x in qqlist:
                    if (qq - x) % 1000000 == 0:
                        qq = x
                        break
                try:
                    qqlist.remove(qq)
                except ValueError:
                    pass

            members = await self.get_group_member(info['code'])

            c = contacts.Add(
                'group', str(uin), name, str(qq), '', mark, members
            )

            if not silence:
                self.logger.info(repr(c))
                for uin, name in members.items():
                    self.logger.info('    成员: %s, uin: %s', name, uin)

        if not silence:
            self.logger.info('获取群列表成功，共 %d 个群' % len(result))

    async def get_group_member(self, gcode):
        ret = await self.smart_request(
            url=('http://s.web2.qq.com/api/get_group_info_ext2?gcode=%s'
                 '&vfwebqq=%s&t={rand}') % (gcode, self.vfwebqq),
            Referer=('http://s.web2.qq.com/proxy.html?v=20130916001'
                     '&callback=1&id=1')
        )

        cards = dict((m['muin'], m['card']) for m in ret['cards'])
        return dict((str(m['muin']), {'nick': str(inf['nick']), 'card': cards.get(m['muin'], None)})
                    for m, inf in zip(ret['ginfo']['members'], ret['minfo']))

    async def get_group_qq(self, uin):
        return (await self.smart_request(
            url=('http://s.web2.qq.com/api/get_friend_uin2?tuin=%s&'
                 'type=4&vfwebqq=%s&t={rand}') % (uin, self.vfwebqq),
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                     'callback=1&id=2'),
            timeoutRetVal={'account': ''}
        ))['account']

    async def get_discusses(self, contacts, silence=False):
        if not silence:
            self.logger.info('登录 Step8 - 获取讨论组列表')

        result = (await self.smart_request(
            url=('http://s.web2.qq.com/api/get_discus_list?clientid=%s&'
                 'psessionid=%s&vfwebqq=%s&t={rand}') %
                (self.client_id, self.psessionid, self.vfwebqq),
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001'
                     '&callback=1&id=2')
        ))['dnamelist']

        for info in result:
            uin = str(info['did'])
            name = str(info['name'])
            members = await self.get_discuss_member(uin)

            c = contacts.Add('discuss', uin, name, members=members)

            if not silence:
                self.logger.info(repr(c))
                for uin, name in members.items():
                    self.logger.info('    成员: %s, uin%s', name, uin)

        if not silence:
            self.logger.info('获取讨论组列表成功，共 %d 个讨论组', len(result))

    async def get_discuss_member(self, uin):
        ret = await self.smart_request(
            url=('http://d1.web2.qq.com/channel/get_discu_info?'
                 'did=%s&psessionid=%s&vfwebqq=%s&clientid=%s&t={rand}') %
                (uin, self.psessionid, self.vfwebqq, self.client_id),
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001'
                     '&callback=1&id=2')
        )
        return dict((str(m['uin']), str(m['nick'])) for m in ret['mem_info'])

    async def poll(self):

        while True:
            try:
                result = await self.smart_request(
                    url='https://d1.web2.qq.com/channel/poll2',
                    data={
                        'r': json.dumps({
                            'ptwebqq': self.ptwebqq, 'clientid': self.client_id,
                            'psessionid': self.psessionid, 'key': ''
                        })
                    },
                    Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                             'callback=1&id=2')
                )
                print(result)
                break
            except tornado.httpclient.HTTPError as e:
                if e.code != 599:
                    raise e
                self.logger.info('长时间未收到信息')

        if not result or 'errmsg' in result:
            return 'timeout', '', '', ''
        else:
            result = result[0]
            ctype = {
                'message': 'buddy',
                'group_message': 'group',
                'discu_message': 'discuss'
            }[result['poll_type']]
            from_uin = str(result['value']['from_uin'])
            member_uin = str(result['value'].get('send_uin', ''))
            content = ''.join(
                ('[face%d]' % m[1]) if isinstance(m, list) else str(m)
                for m in result['value']['content'][1:]
            )
            return ctype, from_uin, member_uin, content

    async def send_message(self, ctype, uin, content, at=None):
        self.msg_id += 1
        send_url = {
            'buddy': 'http://d1.web2.qq.com/channel/send_buddy_msg2',
            'group': 'http://d1.web2.qq.com/channel/send_qun_msg2',
            'discuss': 'http://d1.web2.qq.com/channel/send_discu_msg2'
        }
        send_tag = {'buddy': 'to', 'group': 'group_uin', 'discuss': 'did'}
        result = await self.smart_request(
            url=send_url[ctype],
            data={
                'r': json.dumps({
                    send_tag[ctype]: int(uin),
                    'content': json.dumps([
                        ('@' + at + ' ' if at else '') + content ,
                        ['font', {'name': '宋体', 'size': 10,
                                  'style': [0, 0, 0], 'color': '000000'}]
                    ]),
                    'face': 597,
                    'clientid': self.client_id,
                    'msg_id': self.msg_id,
                    'psessionid': self.psessionid
                })
            },
            Referer=('http://d1.web2.qq.com/proxy.html?v=20151105001&'
                     'callback=1&id=2')
        )

        print(result)
        await tornado.gen.sleep(1 + random.random())

        # if self.msgId % 10 == 0:
        #     self.logger.info('已连续发送10条消息，强制 sleep 10秒，请等待...')
        #     time.sleep(10)
        # else:
        #     time.sleep(random.randint(1, 3))

    async def kick_from_group(self):
        """
        踢人
        :return:
        """
        pass

    async def mute_group(self, gid, enable=False):
        """
        禁言全群
        :return:
        """

        data = {
            'all_shutup': 0xffffffff if enable else 0,
            'gc': gid,
            'src': 'qinfo_v3',
            'bkn': bknHash(self.session.cookiejar['skey'])
        }

        result = await self.smart_request('http://qinfo.clt.qq.com/cgi-bin/qun_info/set_group_shutup',
                                          data=data,
                                          Referer='http://qinfo.clt.qq.com/qinfo_v3/member.html',
                                          )

    async def mute_group_member(self, gid, uin, duration):
        """
        禁言某人
        :return:
        """

        data = {
            'gc': gid,
            'shutup_list': json.dumps([{
                'uin': int(uin),
                't': int(duration)
            }]),
            'src': 'qinfo_v3',
            'bkn': bknHash(self.session.cookiejar['skey'])
        }

        result = await self.smart_request('http://qinfo.clt.qq.com/cgi-bin/qun_info/set_group_shutup',
                                          data=data,
                                          Referer='http://qinfo.clt.qq.com/qinfo_v3/member.html',
                                          )

        return result

    async def get_admins(self, gid):
        url = 'http://qinfo.clt.qq.com/cgi-bin/qun_info/get_admin_auth?auth=1&gc={gid}&bkn={self.bkn}'.format(gid=gid, self=self)

        result = await self.smart_request(url, Referer='http://qinfo.clt.qq.com/qinfo_v3/setting.html?groupuin=' + str(gid))

        return result

    async def get_group_members(self, gid: int):
        url = 'http://qun.qq.com/cgi-bin/qun_mgr/search_group_members'

        data = {
            'gc': gid,
            'st': 0, # start
            'end': 2000,
            'sort': 0,
            'bkn': bknHash(self.session.cookiejar['skey'])
        }

        result = await self.smart_request(url, data=data)

        return result['mems']

    async def exit(self, message=None):
        groups = self.contacts.List('group')

        for group in groups:
            uin = group.uin
            await self.send_message('group', uin, message or "SIGINT 信号已接受，Shina 酱将会进入睡眠.")


def save_account(account):
    account_file = '.{0}.account'.format(account.qq)
    with open(account_file, 'wb') as f:
        data = dict(
            cookies=account.session.cookiejar,
            nick=account.nick,
            qq=account.qq,
            urlPtwebqq=account.urlPtwebqq,
            ptwebqq=account.ptwebqq,
            vfwebqq=account.vfwebqq,
            uin=account.uin,
            psessionid=account.psessionid,
            hash=account.hash,
            bkn=account.bkn
        )

        pickle.dump(data, f)


def load_account(qq):
    try:
        account_file = '.{0}.account'.format(qq)

        account = Account(qq=qq)
        with open(account_file, 'rb') as f:
            data = pickle.load(f)
            account.session.cookiejar = data['cookies']
            account.nick = data['nick']
            account.qq = data['qq']
            account.urlPtwebqq = data['urlPtwebqq']
            account.vfwebqq = data['vfwebqq']
            account.uin = data['uin']
            account.psessionid = data['psessionid']
            account.hash = data['hash']
            account.bkn = data['bkn']
            account.ptwebqq = data['ptwebqq']

        return account
    except:
        return None


try:
    qq = 3267641449
    local_account_object = load_account(qq)
    account = local_account_object or Account(qq=qq)

    if not local_account_object:
        tornado.ioloop.IOLoop.current().run_sync(account.login)
        # login done save object
        save_account(account)
    tornado.ioloop.IOLoop.current().run_sync(account.loop)
except KeyboardInterrupt as e:
    tornado.ioloop.IOLoop.current().stop()
    raise e
