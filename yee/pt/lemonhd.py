# -!- coding: utf-8 -!-
import cgi
import copy
import re
import datetime
from urllib.parse import unquote
from bs4 import BeautifulSoup

from yee.pt.nexusprogramsite import NexusProgramSite
from yee.core.torrentmodels import Torrents, TorrentType, Torrent
from yee.pt.ptsiteparser import PTSiteParser


class LemonHD(NexusProgramSite):
    def get_site(self):
        """
        返回pt站的网址
        :return:
        """
        return 'https://lemonhd.org'

    def get_site_name(self):
        """
        这是pt网站的名称，确保唯一即可，集成到主程序时用作配置项
        :return:
        """
        return 'LemonHD'

    def search_torrent(self, keyword, result_page_limit=5, use_imdb_search: bool = False) -> Torrents:
        return self.automatic_page_loading(
            '%s/torrents.php?search=%s&suggest=0&search_area=%s' % (
                self.get_site(), keyword, 'imdb' if use_imdb_search else 'name'),
            result_page_limit
        )

    def parse_torrents(self, text: str) -> Torrents:
        """
        通过返回的网页代码，解析列表页种子的所有信息
        :param text: 网页源代码
        :return:
        """
        soup = BeautifulSoup(text, features="lxml")
        search_result = []
        # 搜索结果为空的兼容处理
        if not soup.find('table', class_='torrents'):
            return []

        for i, item in enumerate(soup.find('table', class_='torrents').findAll('tr')[1:]):
            rowfollow_tag = item.findAll('td', 'rowfollow')
            if len(rowfollow_tag) != 0:
                t = Torrent()
                t.site_name = self.get_site_name()
                t.site = self.get_site()
                # 获取type/media_source
                find_imgs = rowfollow_tag[0].findAll('img')
                # t.media_source = find_imgs[1].get('title')
                # 获取类型
                t.primitive_type = str(find_imgs[0].get('class')[0])
                if t.primitive_type == 'cat_movie':
                    t.type = TorrentType.Movie
                    t.cate = TorrentType.Movie.value
                elif t.primitive_type == 'cat_tv':
                    t.type = TorrentType.Series
                    t.cate = TorrentType.Series.value
                elif t.primitive_type == 'cat_music':
                    t.type = TorrentType.Music
                    t.cate = TorrentType.Music.value
                elif t.primitive_type == 'cat_doc':
                    t.type = TorrentType.Other
                    t.cate = '纪录片'
                elif t.primitive_type == 'cat_animate':
                    t.type = TorrentType.Other
                    t.cate = '动漫'
                else:
                    t.type = TorrentType.Other
                    t.cate = TorrentType.Other.value
                # 获取 id/name/url
                a_label = rowfollow_tag[2].find('a')
                t_id = a_label.get('href').split('=')[1]
                t.id = int(t_id)
                t.name = str(a_label.find('b').text)
                # t.name = t.name.replace('<b>', '').replace('</b>', '')
                t.url = self.get_site() + '/' + rowfollow_tag[2].find('a',
                                                                      href=lambda value: value and value.startswith(
                                                                          "download")).get('href')
                # 获取object
                if "免费剩余" in rowfollow_tag[2].findAll('div')[2].text:
                    t_free_deadline = re.findall('<span title="([^"]+)"', str(rowfollow_tag[2]))
                    if len(t_free_deadline) == 0:
                        t.free_deadline = datetime.datetime.max
                    else:
                        t.free_deadline = datetime.datetime.strptime(t_free_deadline[0], '%Y-%m-%d %H:%M:%S')
                object_tag = copy.copy(rowfollow_tag[2])
                [s.extract() for s in rowfollow_tag[2].find_all("a")]
                [s.extract() for s in rowfollow_tag[2].find_all("b")]
                [s.extract() for s in rowfollow_tag[2].find_all("div")]
                [s.extract() for s in rowfollow_tag[2].find_all("img")]
                [s.extract() for s in rowfollow_tag[2].find_all("span")]
                subject = rowfollow_tag[2].text.replace('(剩余时间：)', '').strip()
                if subject == '':
                    subject = object_tag.find_all('div')[1].text
                t.subject = str(subject)
                # 获取种子发布时间
                t.publish_time = datetime.datetime.strptime(rowfollow_tag[4].find('span').get('title'),
                                                            '%Y-%m-%d %H:%M:%S')
                # 获取文件大小
                t_file_size_re = re.findall('([1-9]\d*\.?\d*)(TiB|GiB|MiB|KiB|TB|GB|MB|KB)', rowfollow_tag[5].text)
                t.file_size = PTSiteParser.trans_unit_to_mb(float(t_file_size_re[0][0]), t_file_size_re[0][1])
                # 做种人数
                t.upload_count = int(rowfollow_tag[6].text.replace(',', ''))
                # 红种
                if re.findall(r'<font color="(.*?)">\d+</font>', str(rowfollow_tag[6])):
                    t.red_seed = True
                # 下载人数
                t.download_count = int(rowfollow_tag[8].text.replace(',', ''))
                t.movies_release_year = MovieParser.parse_year_by_str_list([t.name, t.subject])
                search_result.append(t)
        return search_result

    # def parse_download_filename(self, response):
    #     if 'Content-Disposition' not in response.headers:
    #         print(response.headers)
    #         return None
    #     value, params = cgi.parse_header(unquote(response.headers['Content-Disposition']))
    #     return params['filename']

    def parse_download_filename(self, response):
        value, params = cgi.parse_header(response.headers['Content-Disposition'])
        filename = params['filename'].encode('ISO-8859-1').decode('utf8')
        return filename
