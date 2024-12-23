import requests, json, re, time
from source import VSourceBase
from datetime import date, timedelta, datetime
from alive_progress import alive_bar
from cprint import CPrint
p = CPrint()

# Patchstack 
class VSource(VSourceBase):
  db_path = 'db/patchstack.json'

  def __init__(self, debug = False):
    super().__init__(debug)
    if debug:
      p.enable_debug(debug)

  def search(self, **kwargs):
    super().search()

    with open(self.db_path, 'r') as fp:
      data = json.load(fp)

    hits = []
    for vid in data:
      vuln = data[vid]
      p.vvv(vuln['title'])

      # Date / Age
      if kwargs['age'] and self.is_old(vuln, kwargs['age']):
        p.vvv('A', prefix="=>")
        continue
      
      # Slug (Plugin / Theme)
      if kwargs['slug'] and vuln['software'][0]['slug'] != kwargs['slug']:
        p.vvv('B', prefix="=>")
        continue

      #CVSS
      if vuln['cvss']['score'] < float(kwargs['cvss_min']) or \
        vuln['cvss']['score'] > float(kwargs['cvss_max']):
        p.vvv('C', prefix="=>")
        continue

      # Auth / UnAuth
      if kwargs['unauth_only'] and not self.is_unauth(vuln):
        p.vvv('D', prefix="=>")
        continue

      # Type
      if kwargs['type'] and self.get_type(vuln) != kwargs['type']:
        p.vvv('E', prefix="=>")
        continue

      p.vvv('Adding: ' + vuln['title'])
      hits.append(vuln)

    return self.format_resp(hits)

  def is_old(self, vuln, age):
    # acc   publ    today
    # |-----|-------|-----|   <-- acc = today - age, if publ > acc => True

    today = date.today()
    delta = timedelta(days = int(age))
    accepted = today - delta

    if datetime.strptime(vuln['published'][:10], '%Y-%m-%d').date() > accepted:
      return False
    else:
      return True

  def format_resp(self, hits):
    out = []
    with alive_bar(len(hits), enrich_print=False) as bar:
      for hit in hits:
        fullname = hit['software'][0]['name']
        name = fullname[:20].rstrip() + '..'if len(fullname) > 20 else fullname

        fullslug = hit['software'][0]['slug']
        slug = fullslug[:30].rstrip() + '..' if len(fullslug) > 30 else fullslug          

        vuln = self.get_type(hit)

        out.append([
          slug,
          vuln,
          hit['cvss']['score'],
          'yes' if self.dot_org(fullslug) else 'no',
          self.dot_org(fullslug) if self.dot_org(fullslug) else '?',
          hit['published'][:10],
          'no' if self.is_unauth(hit) else 'yes',
          'WF',
          ])
        bar()

    return out

  def get_type(self, vuln):

    mapper = {
      "SQL Injection":              'SQLi',
      "Remote Code Execution":      'RCE',
      "Code Injection":             'CODEINJ',
      "Cross-site Scripting":       'XSS',
      "XSS":                        'XSS',
      "Cross-site Request Forgery": 'CSRF',
      "CSRF":                       'CSRF',
      "Server-Side Request Forgery":'SSRF',
      "SSRF":                       'SSRF',
      "Authorization Bypass":       'AUTHBP',
      "Authentication Bypass":      'AUTHBP',
      "Improper Authentication":    'AUTHBP',
      "Improper Authorization":     'AUTHBP',
      "Missing Authorization":      'AUTHBP',
      "Missing Authentication":     'AUTHBP',
      "Unrestricted Upload of File":'RFI',
      "Remote File Inclusion":      'RFI',
      "Arbitrary Folder Deletion":  'LFD',
      "Object Injection":           'OBJINJ',
      "Arbitrary Option Update":    'OPTUPD',
      "Privilege Escalation":       'PRIVESC',
    }

    for string in mapper:
      if string in vuln['cwe']['name'] or string in vuln['title']:
        return mapper[string]

    return 'other' # vuln['cwe']['name']

  def is_unauth(self, vuln):
    p.vvv('looking for unath: ', prefix='>')
    if "unauthenticated" in vuln['title'].lower():
      p.vvv('>> A')
      return True

    if "authenticated" in vuln['title'].lower():
      p.vvv('>> B')
      return False

    user = re.search(r'(subscriber|customer|contributor|editor|administrator)\+',
      vuln['title'].lower())
    if user:
      p.vvv('>> C')
      return False

    p.vvv('>> D')
    return True

  # No Cache
  def update_db(self):
    p.v('Updating Patchstack databse')
    # STEP: Get _token and hash

    with requests.Session() as s:
      resp = s.get('https://patchstack.com/database')
      token = re.search('name="_token" value="(.*?)"', resp.text)
      token = token.group(1)
      ps_hash = re.search("hash: '(.*?)'", resp.text)
      ps_hash = ps_hash.group(1)

      # STEP: Get vuln data

      keep_going = True
      page = 0
      while keep_going:
        page += 1
        headers = {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.1'
        }
        data = {
          'search':     '',
          'cat':        '',
          'range1':     '0',
          'range2':     '10',
          'types[]':    '0',
          'vpatch':     'false',
          'exploited':  'false',
          '_token':     token,
          'page':       page,
          'hash':       ps_hash
        }
        resp = s.post('https://patchstack.com/database/open-source/vulnerabilities/search', data=data)

        ps_json = json.loads(resp.text)
        ps_html = ps_json['html']

        vulns_html = ps_html.split('</a>')
        vulns = {}
        for vuln_html in vulns_html:
          vuln = self.extract_vuln(vuln_html)
          if vuln:
            vulns[vuln['id']] = vuln

        # Only do 1 for debug
        keep_going = False

      with open(self.db_path, 'w+') as fp:
        fp.write(json.dumps(vulns))
        p.v('Database updated')

  def extract_vuln(self, html):
    try:
      out = {
        'link': re.search('<a href="(.*?)"', html).group(1),
        'type': re.search('db-row__type">(.*?)<', html).group(1).lower(),
        'name': re.search('db-row__name-text">(.*?)<', html).group(1),
        'version': re.search('db-row__version--inline">(.*?)<', html).group(1),
        'desc': re.search('db-row__desc">(.*?)<', html).group(1),
        'cvss': re.search(r'db-row__score(.*?)>(.*?)([0-9]\.?[0-9]?)(.*?)<', html, re.DOTALL).group(3),
        'date': re.search('db-row__date">(.*?)<', html).group(1),
      }

      # Slug
      regex = f'database/wordpress/{out["type"]}/(.*?)/vulnerability'
      out['slug'] = re.search(regex, html).group(1)

      # Title
      out['title'] = out['name'] + ' ' + out['desc']

      # Date
      out['date'] = self.real_date(out['date'])

      # CVE
      resp = requests.get(out['link'])
      print(resp.text)
      exit()

      return out
    except:
      return False

  def real_date(self, date_str):
    # 8 days ago -> 2024-12-10
    today = date.today()
    if "hour" in date_str:
      days = 0
    else:
      days = int(re.search('([0-9]{1,3})', date_str).group(1))

    delta = timedelta(days=days)
    real_date = today - delta
    return str(real_date)[:10]
