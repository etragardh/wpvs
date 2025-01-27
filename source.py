from abc import ABC, abstractmethod
from datetime import datetime, date, timedelta
import os, re, requests, time
from cprint import CPrint
from cache import Cache

p = CPrint()

class VSourceBase(ABC):

  init = False

  def __init__(self, debug = False):
    self.init = True
    self.debug = debug

    if debug is not False:
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
      p.v('Updated required (no db)')
      return True

    #       file    accepted    today
    # |-----|-------|-----------|--------       <<-- today > accepted = update!

    #accepted_date = os.path.getmtime(self.db_path)
    today = date.today()
    modified = date.fromtimestamp(os.path.getmtime(self.db_path))
    accepted = date.fromtimestamp(os.path.getmtime(self.db_path) + 24 * 60 * 60)

    # Since we count in whole days, we can just check if today is more than modified
    res = today > modified #accepted
    if res:
      p.v('Updated required')
    else:
      p.v('No update required')
      p.vv(f'today: {today}')
      p.vv(f'modified: {modified}')
      p.vv(f'accepted: {accepted}')

    return res

  def repo_info(self, slug, name, type='plugin'):
    out = {
      'repo':       'unknown',
      'installs':   '-',
      'downloads':  '-'
    }
    headers = {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.1'
    }
    # ==============================
    # STEP: wordpress.org
    url = f'https://wordpress.org/{type}s/{slug}/'

    # False     = We dont have cache
    # Object    = Cached resp
    cache = Cache(url, debug = self.debug)
    if not cache:
      time.sleep(1)
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
        out['repo']     = 'wp.org'
        out['installs'] = installs.group(2)

        # ==============================
        # STEP: wordpress.org/stats api
        url = f'https://wordpress.org/{type}s/{slug}/advanced/'
        url = f'https://api.wordpress.org/stats/plugin/1.0/downloads.php?slug={slug}&historical_summary=1&callback=test'

        cache = Cache(url, debug = self.debug)
        if not cache:
          time.sleep(1)
          resp = requests.get(url, headers=headers, timeout=10)
          if resp.status_code == 429:
            p.warn('Hitting WP.org rate limit, waiting 60s')
            time.sleep(60)
            resp = requests.get(url, headers=headers, timeout=10)
          cache.save(resp)
        else:
          resp = cache

        if resp and resp.status_code == 200:
          downloads = re.search('all_time":"(.*?)"', resp.text)
          if downloads:
            out['downloads'] = "{:,}".format(int(downloads.group(1)))


    # TODO: Continue here
    # Does not work very well - but WF has links to codecanyon and theme forest in their texts on the website.

    # STEP: Code Canyon
    if out['repo'] == 'unknown':
      name_slug = name.replace(' ', '-')
      url = f'https://codecanyon.net/search/{name_slug}'
      p.vv('Looking for canyons at', url, name_slug)

      cache = Cache(url, debug = self.debug)
      if not cache:
        time.sleep(1)
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 429:
          p.warn('Hitting codecanyon.com rate limit, waiting 60s')
          time.sleep(60)
          resp = requests.get(url, headers=headers, timeout=10)
        cache.save(resp)
      else:
        resp = cache

      if resp and resp.status_code == 200:
        # This is the search result:
        url = re.search('href="https://codecanyon.net/item/{name_slug}/(.*?)"', resp.text)
        if not url:
          return out 

        cache = Cache(url, debug = self.debug)
        if not cache:
          time.sleep(1)
          resp = requests.get(url, headers=headers, timeout=10)
          if resp.status_code == 429:
            p.warn('Hitting codecanyon.com rate limit, waiting 60s')
            time.sleep(60)
            resp = requests.get(url, headers=headers, timeout=10)
          cache.save(resp)
        else:
          resp = cache

        if resp and resp.status_code == 200:
          out['repo'] = 'cc.com'
          out['downloads'] = re.search('<strong>(.*?)</strong> sales', resp.text).group(1)

    return out 

  def get_type(self, haystack, default = 'other'):
        
    mapper = {
      "SQL Injection":                    'SQLi',
      "Remote Code Execution":            'RCE',
      "Code Injection":                   'CODEINJ',
      "Cross-site Scripting":             'XSS',
      "XSS":                              'XSS',
      "Cross-site Request Forgery":       'CSRF',
      "CSRF":                             'CSRF',
      "Server-Side Request Forgery":      'SSRF',
      "SSRF":                             'SSRF',
      "Authorization Bypass":             'AUTHBP',
      "Authentication Bypass":            'AUTHBP',
      "Improper Authentication":          'AUTHBP',
      "Improper Authorization":           'AUTHBP',
      "Unrestricted Upload of File":      'RFI',
      "Remote File Inclusion":            'RFI',
      "Local File Inclusion":             'LFI',
      "Local PHP Inclusion":              'LFI',
      "Arbitrary Folder Deletion":        'LFD',
      "Object Injection":                 'OBJINJ',
      "Arbitrary Option Update":          'OPTUPD',
      "Privilege Escalation":             'PRIVESC',
      "Post Disclosure":                  'DATALEAK',
      "Arbitrary File Download":          'FILEDL',
      "Arbitrary Shortcode Execution":    'ARBSHCODE',
      "Arbitrary File Upload":            'RFI',
      "Arbitrary Directory Deletion":     'ARBDDEL',
      "Arbitrary User Token Generation":  'AUTHBP',
      "Missing Authorization":            'AUTHBP',
      "Missing Authentication":           'AUTHBP',
    }

    for string in mapper:
      if string.lower() in haystack.lower():
        return mapper[string]

    return default #vuln['title'] #'other' # vuln['cwe']['name']

  def is_unauth(self, haystack):
    p.vvv('looking for unath: ', prefix='>')
    if "unauthenticated" in haystack.lower():
      p.vvv('>> A')
      return True

    if "authenticated" in haystack.lower():
      p.vvv('>> B')
      return False

    user = re.search(r'(subscriber|customer|contributor|editor|administrator)\+',
      haystack.lower())
    if user:
      p.vvv('>> C')
      return False

    p.vvv('>> D')
    return True

  def is_old(self, published, age):
    # acc   publ    today
    # |-----|-------|-----|   <-- acc = today - age, if publ > acc => True

    today = date.today()
    delta = timedelta(days = int(age))
    accepted = today - delta

    if datetime.strptime(published[:10], '%Y-%m-%d').date() > accepted:
      return False
    else:
      return True
