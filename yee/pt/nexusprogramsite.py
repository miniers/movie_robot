import html
import io
import logging
import os
import re
import zipfile
from abc import ABCMeta, abstractmethod
from urllib.parse import urlparse

from yee.core.httputils import RequestUtils
from yee.core.stringutils import StringUtils
from yee.core.torrentmodels import Torrents, FileTorrent
from yee.pt.ptsite import PTSite


class NexusProgramSite(PTSite, metaclass=ABCMeta):
    headers = {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36'
    }
    cookies = None
    req = RequestUtils(request_interval_mode=True)

    def login(self, username: str, password: str):
        raise RuntimeError('%s不支持用户名密码登陆' % (self.get_site_name()))

    def match_user(self, text):
        if text is None or text.strip() == '':
            return None
        match_login_user = re.search(r'class=[\'"][^\'"]+[\'"]>(?:<a.+>)<b>(.+)</b>.*</a>.*</span>', text)
        if match_login_user:
            return StringUtils.trimhtml(match_login_user.group(1))
        else:
            return None

    def handle_cf_check(self, res):
        if res.text.find('data-cf-settings') != -1 and res.text.find('rocket-loader') != -1:
            match_js_var = re.search(r'window.location=(.+);', res.text)
            if match_js_var:
                check_uri = eval(match_js_var.group(1))
                res = self.req.get(
                    url=self.get_site() + check_uri,
                    headers=self.headers,
                    cookies=self.cookie_jar,
                    skip_check=True
                )
                return res
        return res

    def login_by_cookie(self, cookie: str):
        parsed = urlparse(self.get_site())
        cookie_jar = self.req.cookiestr_to_jar(cookie, parsed.hostname)
        res = self.req.get(
            url=self.get_site(),
            headers=self.headers,
            cookies=cookie_jar,
            skip_check=True
        )
        self.cookies = cookie_jar
        if res is None:
            raise RuntimeError('%s登陆失败。' % self.get_site_name())
        res = self.handle_cf_check(res)
        user = self.match_user(res.text)
        if user is None:
            raise RuntimeError('%s登陆失败。' % self.get_site_name())
        logging.info('%s登陆成功，欢迎回来：%s' % (parsed.hostname, StringUtils.noisestr(user)))

    def get_torrent_list(self, url, result_page_limit=5) -> Torrents:
        return self.automatic_page_loading(url, result_page_limit)

    def search_torrent(self, keyword, result_page_limit=5, use_imdb_search: bool = False) -> Torrents:
        return self.automatic_page_loading(
            '%s/torrents.php?incldead=1&spstate=0&inclbookmarked=0&search=%s&search_area=%s&search_mode=0' % (
                self.get_site(), keyword, '4' if use_imdb_search else '0'),
            result_page_limit
        )

    def automatic_page_loading(self, url, result_page_limit=5) -> Torrents:
        parsed = urlparse(url)
        if parsed.query != '':
            query_str = '?' + parsed.query
        else:
            query_str = ''
        search_result = []
        while query_str is not None:
            res = self.req.get(
                url='%s://%s%s%s' % (parsed.scheme, parsed.hostname, parsed.path, query_str),
                cookies=self.cookies,
                headers=self.headers,
                flaresolverr=self.kwargs['flaresolverr']
            )
            if res is None:
                break
            self.cookies.update(res.cookies)
            res = self.handle_cf_check(res)
            text = res.text
            match_page = re.search(r'<a href="(\?[^"]+page=(\d+))"><b(?:\s+title="Alt\+Pagedown")?>下一[頁页]', text)
            page_result = self.parse_torrents(text)
            if page_result is not None and len(page_result) > 0:
                search_result = search_result + page_result
            if match_page:
                query_str = html.unescape(match_page.group(1))
                if not int(match_page.group(2)) < result_page_limit:
                    break
            else:
                query_str = None
        return search_result

    @abstractmethod
    def parse_download_filename(self, response):
        pass

    def download_torrent(self, url, save_dir) -> FileTorrent:
        r = self.req.post_res(url, headers={
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'referer': self.get_site() + '/torrents.php',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36'
        }, cookies=self.cookies, allow_redirects=False)
        if r.status_code != 200 and r.status_code != 302:
            logging.info('种子下载失败(%s)：%s' % (r.status_code, url))
            return None
        ft = FileTorrent()
        filename = self.parse_download_filename(r)
        if filename is None:
            logging.info('无法下载种子：%s' + url)
            return None
        ft.url = r.url
        ft.name = os.path.splitext(filename)[0]
        if os.path.splitext(filename)[-1] == '.zip':
            torrent_filename = None
            zfile = zipfile.ZipFile(io.BytesIO(r.content))
            for item in zfile.namelist():
                cn_name = item.encode('cp437').decode('gbk')
                if os.path.splitext(item)[-1] == '.torrent':
                    torrent_filename = cn_name
                    zfile.extract(item, save_dir + os.sep)
                    os.rename(save_dir + os.sep + item, save_dir + os.sep + cn_name)
            zfile.close()
            if torrent_filename is None:
                logging.info('错误的种子zip压缩包，请人工检查确认%s' % filename)
                return None
            else:
                ft.filepath = save_dir + os.sep + torrent_filename
        else:
            ft.filepath = save_dir + os.sep + filename
            with open(ft.filepath, 'wb') as f:
                f.write(r.content)
        return ft
