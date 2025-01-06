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
      if kwargs['age'] and self.is_old(vuln['published'], kwargs['age']):
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
      if kwargs['unauth_only'] and not self.is_unauth(vuln['title']):
        p.vvv('D', prefix="=>")
        continue

      # Type
      if kwargs['type'] and self.get_type(vuln['title']) not in kwargs['type']:
        p.vvv('E', prefix="=>")
        continue

      p.vvv('Adding: ' + vuln['title'])
      #progress = i / count * 100
      #p.progress(progress)
      hits.append(vuln)

    return self.format_resp(hits)

  def format_resp(self, hits):
    out = []
    with alive_bar(len(hits), enrich_print=False) as bar:
      for hit in hits:
        fullname = hit['software'][0]['name']
        name = fullname[:20].rstrip() + '..'if len(fullname) > 20 else fullname

        fullslug = hit['software'][0]['slug']
        slug = fullslug[:30].rstrip() + '..' if len(fullslug) > 30 else fullslug          

        vuln = self.get_type(hit['title'])

        repo = self.repo_info(fullslug, fullname)

        out.append([
          slug,
          vuln,
          hit['cvss']['score'],
          'no' if not self.is_fixed(hit) else self.is_fixed(hit),
          'no' if self.is_unauth(hit['title']) else 'yes',
          repo['repo'],
          repo['installs'],
          repo['downloads'],
          hit['published'][:10],
          'WF',
          ])
        bar()

    return out

  def is_fixed(self, vuln):
    if vuln['software'][0]['patched']:
      return vuln['software'][0]['patched_versions'][0]
    else:
      return False

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
