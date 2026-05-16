import json, sys
for line in sys.stdin:
    h = json.loads(line)
    if 'github' in h['fqdn'] and h['scope']['status'] == 'out':
        print(h['fqdn'], h['scope']['matched_rule'])
        break