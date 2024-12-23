from abc import ABC, abstractmethod
from datetime import date
import os, re, requests, time
from cprint import CPrint
from cache import Cache

p = CPrint()

class VSourceBase(ABC):

  init = False

  def __init__(self, debug = False):
    self.init = True
    self.debug = debug

    if debug:
      p.enable_debug(debug)

  @property
  @abstractmethod
  def db_path(self):
    pass

  @abstractmethod
  def update_db(self):
    pass

  @abstractmethod
  def search(self, **kwargs):
    if self.is_db_update_required():
      self.update_db()

  def is_db_update_required(self):
    p.v(f'Checking database timestamp: {self.db_path}')

    if not os.path.exists(self.db_path):
      return True

    #       file    accepted    today
    # |-----|-------|-----------|--------       <<-- today > accepted = update!

    #accepted_date = os.path.getmtime(self.db_path)
    today = date.today()
    modified = date.fromtimestamp(os.path.getmtime(self.db_path))
    accepted = date.fromtimestamp(os.path.getmtime(self.db_path) + 24 * 60 * 60)

    res = today > accepted
    if res:
      p.v('Updated required')
    else:
      p.v('No update required')

    return today > accepted

  def dot_org(self, slug, type='plugin'):
    url = f'https://wordpress.org/{type}s/{slug}'

    # False     = We dont have cache
    # Object    = Cached resp
    cache = Cache(url, debug = self.debug)
    if not cache:
      time.sleep(1)
      headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.1'
      }
      resp = requests.get(url, headers=headers, timeout=10)
      if resp.status_code == 429:
        p.warn('Hitting WP.org rate limit, waiting 60s')
        time.sleep(60)
        resp = requests.get(url, headers=headers, timeout=10)
      cache.save(resp)
    else:
      resp = cache

    if resp and resp.status_code == 200:
      # This might be a dot org plugin/theme
      installs = re.search('Active installations(.*?)<strong>(.*?)</strong>', resp.text)
      if installs:
        return installs.group(2)

    # It was not
    return False


