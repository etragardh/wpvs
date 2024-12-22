import requests, json, hashlib, os
from cprint import CPrint

p = CPrint()

class Cache:
  status_code     = False
  text            = False
  json_data       = False

  def __init__(self, url, base='cache/', debug = False):
    self.url = url
    self.base = base

    if debug:
      p.enable_debug(debug)

    self._prepare_resp(url)

  def __bool__(self):
    return self.status_code != False

  def json(self):
    if self.json:
      try:
        return json.loads(self.json)
      except:
        return False
    else:
      return False

  def _prepare_resp(self, url):
    p.vvv('Looking for cached req:' + url)
    path = self._path(url)
    if os.path.exists(path):
      p.vvv('We have cache', prefix=">")
      with open(path, 'r') as fp:
        data = json.loads(fp.read())
#        data = fp.read()

      self.text         = data['text']
      self.json_data    = data['json']
      self.status_code  = data['status_code']
    else:
      p.vvv('We did not have any cache', prefix=">")

  def _path(self, url):
    hash = self._hash(url)
    dirs = f"{self.base}{hash[:2]}/{hash[2:4]}"
    os.makedirs(dirs, exist_ok=True)
    path = f"{dirs}/{hash}"
    return path

  def _hash(self, string):
    return hashlib.md5(string.encode()).hexdigest()

  def save(self, response):
    p.vvv('Save cache')
    path = self._path(self.url)

    try:
      json_data = response.json()
    except:
      json_data = False

    data = {
      'text':         response.text,
      'json':         json_data,
      'status_code':  response.status_code
    }
    with open(path, 'w+') as fp:
      fp.write(json.dumps(data))
