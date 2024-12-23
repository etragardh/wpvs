import requests, json, re, time
from source import VSourceBase
from datetime import date, timedelta, datetime
from alive_progress import alive_bar
from cprint import CPrint
p = CPrint()

# Wordfence
class VSource(VSourceBase):
  db_path = 'db/wordfence.json'

  def __init__(self, debug = False):
    super().__init__(debug)
    if debug:
      p.enable_debug(debug)

  def search(self, **kwargs):
    super().search()

    with open(self.db_path, 'r') as fp:
      data = json.load(fp)

    hits = []
    #i = 0
    #count = len(data)
    for vid in data:
      #i += 1

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
      #progress = i / count * 100
      #p.progress(progress)
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
    p.info('Updating Wordfence databse')
    resp = requests.get('https://wordfence.com/api/intelligence/v2/vulnerabilities/production') 
    if resp and resp.status_code == 200:
      with open(self.db_path, 'w+') as fp:
        fp.write(resp.text)
        p.v('Database updatad')

    else:
      p.error('Database update failed')
