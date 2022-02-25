import datetime
import logging
import random
import time
from http.cookiejar import Cookie
from urllib.parse import urlencode

import requests
import urllib3
from requests.cookies import RequestsCookieJar
from requests.models import Response

class RequestUtils:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    __pre_request_time = None

    def __init__(self, request_interval_mode=False):
        self.request_interval_mode = request_interval_mode

    def cookiestr_to_jar(self, cookiestr, domain):
        cookie_arr = cookiestr.split(';')
        cookie_jar = RequestsCookieJar()
        # 默认设30天过期
        expire = round(time.time()) + 60 * 60 * 24 * 30
        for c in cookie_arr:
            c = c.strip()
            if c == '':
                continue
            pair = c.split('=')
            cookiestr = Cookie(0, pair[0], pair[1], None, False, domain, False, False, '/', True, True, expire,
                               False, None,
                               None, [], False)
            cookie_jar.set_cookie(cookiestr)
        return cookie_jar
    def cookiedict_to_jar(self,cookies):
        cookie_jar = RequestsCookieJar()
         # 默认设30天过期
        expire = round(time.time()) + 60 * 60 * 24 * 30
        for c in cookies:
            cookiestr = Cookie(0, c['name'], c['value'], None, False, c['domain'], False, False, '/', True, c['secure'], c['expires'] if c['expires'] >0 else expire,
                               False, None,
                               None, [], False)
            cookie_jar.set_cookie(cookiestr)
        return cookie_jar
    def cookiejar_to_dict(self, cookie):
        return [
            {'name': c.name, 'value': c.value, 'domain': c.domain,
                'path': c.path, 'url': '', 'expires': c.expires, 'secure': c.secure}
            for c in cookie
        ]
    def check_request(self):
        if not self.request_interval_mode:
            return
        """
        todo 对不同domain做不同配置
        检测每次请求的间隔，如果频率太快则休息，休息时间尽量无规律
        :return:
        """
        if self.__pre_request_time is None:
            self.__pre_request_time = datetime.datetime.now()
            return
        during_time = datetime.datetime.now() - self.__pre_request_time
        ms = during_time.microseconds / 1000
        # 至少间隔1秒，随机是为了无规律
        if ms < random.randint(1000, 5000):
            min_sleep_secs = 1
            # 随机休眠0.5-5秒，扣除间隔影响，避免休眠太久
            max_sleep_secs = 10.0 - (ms / 1000)
            # 避免间隔太久随机出错
            if max_sleep_secs <= min_sleep_secs:
                max_sleep_secs = min_sleep_secs * 2
            sleep_secs = random.uniform(min_sleep_secs, max_sleep_secs)
            time.sleep(sleep_secs)
        self.__pre_request_time = datetime.datetime.now()

    def init_flaresolverr_session(self, flaresolverr, session):
        res = requests.post(url=flaresolverr + '/v1', json={
            'cmd': 'sessions.list',
        }, headers={
            "Content-Type": "application/json"
        }).json()
        if len(res['sessions']) < 1 or session not in res['sessions']:
            requests.post(url=flaresolverr + '/v1', json={
                'cmd': 'sessions.create',
                'session': session
            }, headers={
                "Content-Type": "application/json"
            })

    def request(self, url, method='get', flaresolverr=None, param=None, data=None, **kwargs):
        kwargs.setdefault('verify', False)
        kwargs.setdefault('headers', {})
        kwargs.setdefault('cookies', None)
        kwargs.setdefault('allow_redirects', True)
        if flaresolverr is not None:
            self.init_flaresolverr_session(flaresolverr, 'movie_robot')
            json = {
                'cmd': 'request.' + method,
                'url': url,
                'session': 'movie_robot',
                'cookies': [] if kwargs['cookies'] is None else self.cookiejar_to_dict(kwargs['cookies'])
            }
            if method == 'post':
                json['postData'] = urlencode(data)
            r = requests.post(url=flaresolverr + '/v1', json=json, headers={
                "Content-Type": "application/json"
            }).json()
            response = Response()
            if 'solution' in r.keys():
                res = r["solution"]
                response.url = res['url']
                response.cookies = self.cookiedict_to_jar(res['cookies'])
                response.headers = res['headers']
                response.status_code = res['status']
                response._content = res['response'].encode('utf-8')
            else:
                response.status_code = 500
                response._content = r['message'].encode('utf-8')
            return response
        else:
            if method == 'post':
                kwargs.setdefault('data', data)
                return requests.post(url, **kwargs)
            else:
                return requests.get(url, **kwargs)

    def post(self, url, params=None, headers=None, flaresolverr=None):
        i = 0
        while i < 3:
            try:
                self.check_request()
                r = requests.post(url, data=params,
                                  verify=False, headers=headers)
                return str(r.content, 'UTF-8')
            except requests.exceptions.RequestException as e:
                i += 1
                logging.info('请求%s 失败，开始准备重试(%s/3)' % (url, i))
                logging.info("错误信息：%s" % e)

    def get_text(self, url, params=None, headers=None, flaresolverr=None):
        i = 0
        while i < 3:
            try:
                self.check_request()
                r = requests.get(url, verify=False, headers=headers, params=params)
                return str(r.content, 'UTF-8')
            except requests.exceptions.RequestException as e:
                i += 1
                logging.info('请求%s 失败，开始准备重试(%s/3)' % (url, i))
                logging.info("错误信息：%s" % e)

    def get(self, url, params=None, headers=None, cookies=None, skip_check=False, verify=False, allow_redirects=True, flaresolverr=None):
        i = 0
        while i < 3:
            try:
                if not skip_check:
                    self.check_request()
                return self.request(url, method='get', params=params, verify=verify, headers=headers, cookies=cookies, flaresolverr=flaresolverr,
                                    allow_redirects=allow_redirects)
            except requests.exceptions.RequestException as e:
                i += 1
                logging.info('请求%s 失败，开始准备重试(%s/3)' % (url, i))
                logging.info("错误信息：%s" % e)

    def post_res(self, url, params=None, headers=None, cookies=None, allow_redirects=True, skip_check=False, flaresolverr=None):
        i = 0
        while i < 3:
            try:
                if not skip_check:
                    self.check_request()
                return self.request(url, method='post', data=params, verify=False, headers=headers, cookies=cookies, flaresolverr=flaresolverr,
                                     allow_redirects=allow_redirects)
            except requests.exceptions.RequestException as e:
                i += 1
                logging.info('请求%s 失败，开始准备重试(%s/3)' % (url, i))
                logging.info("错误信息：%s" % e)

    def post_json(self, url, json=None, headers=None, cookies=None, allow_redirects=True, skip_check=False,flaresolverr=None):
        i = 0
        while i < 3:
            try:
                if not skip_check:
                    self.check_request()
                return requests.post(url, json=json, verify=False, headers=headers, cookies=cookies, flaresolverr=flaresolverr,
                                     allow_redirects=allow_redirects)
            except requests.exceptions.RequestException as e:
                i += 1
                logging.info('请求%s 失败，开始准备重试(%s/3)' % (url, i))
                logging.info("错误信息：%s" % e)
