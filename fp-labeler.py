#!/usr/bin/env python3
"""
Rule-based Auto Labeler — No third-party API
Kriteria FP/TP didefinisikan independen dari data Wazuh
"""
import json
from collections import Counter

ALERTS_LOG  = "/var/ossec/logs/alerts/alerts.json"
LABELED_OUT = "/home/azureuser/labeled_alerts.jsonl"

# ============================================================
# KRITERIA FALSE POSITIVE
# ============================================================
FP_RULE_IDS = {
    '5501','5502',   # PAM session open/close (normal)
    '5402','5403',   # Sudo normal
    '510',           # Syslog info
    '502',           # Ossec started
    '651','652',     # Syscheck normal
    '19007','19008', # CIS compliance info
    '5715',          # SSH auth success (legitimate)
    '5762',          # SSH connection reset (noise)
    '2901',          # Dpkg requested (system update)
    '2902',          # Dpkg installed (system update)
    '2904',          # Dpkg half configured (system update)
}

def is_fp(a):
    # Rule ID yang diketahui FP
    if a['rule_id'] in FP_RULE_IDS:
        return True
    # Level sangat rendah tanpa MITRE = noise
    if a['level'] <= 3:
        return True
    # Level 4 tanpa MITRE dan hanya sekali = noise
    if a['level'] == 4 and not a['mitre_ids'] and a['firedtimes'] == 1:
        return True
    # Web 400 error sedikit = bot scan normal
    if a['rule_id'] == '31101' and a['firedtimes'] <= 3:
        return True
    # Syscheck low level
    if 'syscheck' in a['groups'] and a['level'] < 7:
        return True
    return False

# ============================================================
# KRITERIA TRUE POSITIVE
# ============================================================
TP_MITRE = {
    'T1110','T1110.001',  # Brute Force
    'T1059',              # Command execution
    'T1021.004',          # SSH abuse
    'T1078',              # Valid account abuse
    'T1190',              # Exploit public app
    'T1498',              # DDoS
    'T1566',              # Phishing
    'T1003',              # Credential dumping
}

TP_GROUPS = {'attack', 'malware', 'web', 'exploit'}

def is_tp(a):
    # Brute force confirmed rules
    if a['rule_id'] in {'5551','5712','5763','31151'}:
        return True
    # High level = serious alert
    if a['level'] >= 10:
        return True
    # Multiple failed SSH login = serangan aktif
    if a['rule_id'] in {'5710','5503','5760'} and a['firedtimes'] >= 3:
        return True
    # Web attack repeated
    if a['rule_id'] == '31101' and a['firedtimes'] >= 5:
        return True
    # Suspicious URL access
    if a['rule_id'] == '31516':
        return True
    # MITRE ATT&CK match
    if bool(TP_MITRE & set(a['mitre_ids'])):
        return True
    # Level 7+ repeated
    if a['level'] >= 7 and a['firedtimes'] >= 3:
        return True
    return False

# ============================================================
# FEATURE EXTRACTION
# ============================================================
def extract(raw):
    rule  = raw.get('rule', {})
    agent = raw.get('agent', {})
    data  = raw.get('data', {})
    ts    = raw.get('timestamp', '2000-01-01T00:00:00')
    try:
        hour = int(ts[11:13])
    except:
        hour = 12

    return {
        'alert_id':     raw.get('id', ''),
        'timestamp':    ts,
        'rule_id':      str(rule.get('id', '0')),
        'level':        int(rule.get('level', 0)),
        'firedtimes':   int(rule.get('firedtimes', 1)),
        'description':  rule.get('description', ''),
        'groups':       rule.get('groups', []),
        'mitre_ids':    rule.get('mitre', {}).get('id', []),
        'agent_id':     str(agent.get('id', '000')),
        'agent_name':   agent.get('name', ''),
        'srcip':        data.get('srcip', ''),
        'has_srcip':    1 if data.get('srcip') else 0,
        'has_srcuser':  1 if data.get('srcuser') else 0,
        'mail':         1 if rule.get('mail') else 0,
        'gdpr':         1 if rule.get('gdpr') else 0,
        'pci_dss':      1 if rule.get('pci_dss') else 0,
        'hour':         hour,
        'is_night':     1 if hour < 6 or hour > 22 else 0,
        'groups_count': len(rule.get('groups', [])),
        'mitre_count':  len(rule.get('mitre', {}).get('id', [])),
    }

# ============================================================
# MAIN
# ============================================================
def run():
    print("=" * 55)
    print("   Wazuh Rule-Based Auto Labeler")
    print("   No third-party API")
    print("=" * 55)

    stats   = Counter()
    labeled = []

    with open(ALERTS_LOG) as f:
        for line in f:
            try:
                feat = extract(json.loads(line.strip()))
                if is_fp(feat):
                    feat['verdict'] = 'FP'
                elif is_tp(feat):
                    feat['verdict'] = 'TP'
                else:
                    feat['verdict'] = 'UNCERTAIN'
                stats[feat['verdict']] += 1
                labeled.append(feat)
            except:
                stats['error'] += 1

    total = stats['FP'] + stats['TP'] + stats['UNCERTAIN']
    print(f"\n[*] Total diproses  : {total}")
    print(f"    FP              : {stats['FP']} ({stats['FP']/total*100:.1f}%)")
    print(f"    TP              : {stats['TP']} ({stats['TP']/total*100:.1f}%)")
    print(f"    UNCERTAIN       : {stats['UNCERTAIN']} ({stats['UNCERTAIN']/total*100:.1f}%)")
    print(f"    Error           : {stats['error']}")

    # Simpan hanya FP dan TP untuk training
    with open(LABELED_OUT, 'w') as f:
        for item in labeled:
            if item['verdict'] != 'UNCERTAIN':
                f.write(json.dumps(item) + '\n')

    training_total = stats['FP'] + stats['TP']
    print(f"\n[*] Training data saved : {training_total} alerts → {LABELED_OUT}")

    # Detail breakdown per rule
    print(f"\n[*] FP breakdown per rule:")
    fp_rules = Counter()
    tp_rules = Counter()
    for item in labeled:
        if item['verdict'] == 'FP':
            fp_rules[f"{item['rule_id']} | {item['description'][:40]}"] += 1
        elif item['verdict'] == 'TP':
            tp_rules[f"{item['rule_id']} | {item['description'][:40]}"] += 1

    for r, c in fp_rules.most_common(10):
        print(f"    {c:>5}x  {r}")

    print(f"\n[*] TP breakdown per rule:")
    for r, c in tp_rules.most_common(10):
        print(f"    {c:>5}x  {r}")

    return labeled, stats

if __name__ == "__main__":
    run()
