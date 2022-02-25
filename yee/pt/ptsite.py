from abc import ABCMeta, abstractmethod

from yee.core.torrentmodels import FileTorrent, Torrents

"""
PT站操作类
"""
class PTSite(metaclass=ABCMeta):
    def __init__(self, **kwargs):
        kwargs.setdefault('type', 'cookie')
        kwargs.setdefault('flaresolverr', None)
        self.kwargs = kwargs
        if kwargs['type'] == 'user':
            self.login(kwargs['username'], kwargs['password'])
        elif kwargs['type'] == 'cookie':
            self.login_by_cookie(kwargs['cookie'])
        else:
            raise RuntimeError('错误的登陆类型：%s' % kwargs['type'])

    @abstractmethod
    def get_site(self):
        pass

    @abstractmethod
    def get_site_name(self):
        pass

    @abstractmethod
    def login(self, username: str, password: str):
        pass

    @abstractmethod
    def login_by_cookie(self, cookie: str):
        pass

    @abstractmethod
    def parse_torrents(self, text: str) -> Torrents:
        pass

    @abstractmethod
    def get_torrent_list(self, url, result_page_limit=5) -> Torrents:
        pass

    @abstractmethod
    def search_torrent(self, keyword, result_page_limit=5, use_imdb_search: bool = False) -> Torrents:
        pass

    @abstractmethod
    def download_torrent(self, url, save_dir) -> FileTorrent:
        pass
