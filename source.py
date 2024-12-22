from abc import ABC, abstractmethod
from datetime import date
import os, re, requests
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
      resp = requests.get(url)
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


