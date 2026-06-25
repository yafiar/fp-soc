#!/usr/bin/env python3
"""
Wazuh Local AI FP Detector
Random Forest + Isolation Forest
No third-party API
"""
import json
import numpy as np
import pickle
import time
from collections import Counter
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sklearn.utils import resample

LABELED_DATA = "/home/azureuser/labeled_alerts.jsonl"
ALERTS_LOG   = "/var/ossec/logs/alerts/alerts.json"
MODEL_RF     = "/home/azureuser/model-rf.pkl"
MODEL_IF     = "/home/azureuser/model-if.pkl"
ENCODERS     = "/home/azureuser/model-encoders.pkl"
CURATED_LOG  = "/home/azureuser/curated-alerts.log"

FEATURE_COLS = [
    'rule_id_enc', 'level', 'firedtimes', 'agent_id_enc',
    'has_srcip', 'has_srcuser', 'mail', 'gdpr', 'pci_dss',
    'groups_count', 'mitre_count', 'hour', 'is_night'
]

def build_features(alert, encoders=None):
    try:
        hour = int(alert.get('timestamp', '00:00')[11:13])
    except:
        hour = 12

    rule_id  = str(alert.get('rule_id',  alert.get('rule',  {}).get('id',  '0')))
    agent_id = str(alert.get('agent_id', alert.get('agent', {}).get('id', '000')))

    row = {
        'rule_id':      rule_id,
        'level':        int(alert.get('level',      alert.get('rule', {}).get('level', 0))),
        'firedtimes':   int(alert.get('firedtimes', alert.get('rule', {}).get('firedtimes', 1))),
        'agent_id':     agent_id,
        'has_srcip':    int(alert.get('has_srcip',  1 if alert.get('data', {}).get('srcip') else 0)),
        'has_srcuser':  int(alert.get('has_srcuser',1 if alert.get('data', {}).get('srcuser') else 0)),
        'mail':         int(alert.get('mail',    0)),
        'gdpr':         int(alert.get('gdpr',    0)),
        'pci_dss':      int(alert.get('pci_dss', 0)),
        'groups_count': len(alert.get('groups',    alert.get('rule', {}).get('groups', []))),
        'mitre_count':  len(alert.get('mitre_ids', alert.get('rule', {}).get('mitre', {}).get('id', []))),
        'hour':         hour,
        'is_night':     1 if hour < 6 or hour > 22 else 0,
    }

    if encoders:
        for col in ['rule_id', 'agent_id']:
            le  = encoders[col]
            val = str(row[col])
            row[f'{col}_enc'] = le.transform([val])[0] if val in le.classes_ else 0
    
    return row

def train():
    print("=" * 60)
    print("   Wazuh Local AI FP Detector — Training")
    print("   Random Forest + Isolation Forest")
    print("=" * 60)

    # Load labeled data
    print("\n[1/5] Loading labeled data...")
    rows, targets = [], []
    with open(LABELED_DATA) as f:
        for line in f:
            try:
                d = json.loads(line)
                rows.append(d)
                targets.append(1 if d['verdict'] == 'TP' else 0)
            except:
                pass

    tp_n = sum(targets)
    fp_n = len(targets) - tp_n
    print(f"      Total  : {len(rows)}")
    print(f"      TP     : {tp_n} ({tp_n/len(targets)*100:.1f}%)")
    print(f"      FP     : {fp_n} ({fp_n/len(targets)*100:.1f}%)")

    # Fit encoders
    print("\n[2/5] Fitting encoders...")
    encoders = {
        'rule_id':  LabelEncoder().fit([str(r.get('rule_id', '0')) for r in rows]),
        'agent_id': LabelEncoder().fit([str(r.get('agent_id', '000')) for r in rows]),
    }

    # Build feature matrix
    print("\n[3/5] Building feature matrix...")
    feature_rows = []
    for r in rows:
        feat = build_features(r, encoders)
        feature_rows.append([feat[c] for c in FEATURE_COLS])

    X = np.array(feature_rows)
    y = np.array(targets)

    # Oversample minority class (FP) untuk balance
    X_tp = X[y == 1]
    y_tp = y[y == 1]
    X_fp = X[y == 0]
    y_fp = y[y == 0]

    X_fp_up, y_fp_up = resample(
        X_fp, y_fp,
        replace=True,
        n_samples=len(X_tp) // 2,
        random_state=42
    )

    X_balanced = np.vstack([X_tp, X_fp_up])
    y_balanced = np.hstack([y_tp, y_fp_up])
    print(f"      After oversample — TP: {sum(y_balanced==1)}, FP: {sum(y_balanced==0)}")

    # Train Isolation Forest
    print("\n[4/5] Training models...")
    contamination = max(0.05, min(fp_n / len(targets), 0.45))
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42
    )
    iso.fit(X)
    print(f"      Isolation Forest trained (contamination={contamination:.2f})")

    # Train Random Forest
    X_train, X_test, y_train, y_test = train_test_split(
        X_balanced, y_balanced,
        test_size=0.2,
        random_state=42,
        stratify=y_balanced
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        class_weight='balanced',
        max_depth=10,
        min_samples_leaf=2,
        random_state=42
    )
    rf.fit(X_train, y_train)
    print(f"      Random Forest trained")

    # Evaluate
    print("\n[5/5] Evaluasi model...")
    y_pred = rf.predict(X_test)
    print(classification_report(
        y_test, y_pred,
        target_names=['FP', 'TP'],
        zero_division=0
    ))

    cm = confusion_matrix(y_test, y_pred)
    print(f"      Confusion Matrix:")
    print(f"        TN (FP benar suppress) : {cm[0][0]}")
    print(f"        FP error (FP → TP)     : {cm[0][1]}")
    print(f"        FN (TP terlewat)        : {cm[1][0]}")
    print(f"        TP benar detect         : {cm[1][1]}")

    # Cross validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_f1 = cross_val_score(rf, X_balanced, y_balanced, cv=cv, scoring='f1')
    cv_pr = cross_val_score(rf, X_balanced, y_balanced, cv=cv, scoring='precision')
    cv_rc = cross_val_score(rf, X_balanced, y_balanced, cv=cv, scoring='recall')
    print(f"\n      Cross-validation (5-fold):")
    print(f"        F1        : {cv_f1.mean():.3f} ± {cv_f1.std():.3f}")
    print(f"        Precision : {cv_pr.mean():.3f} ± {cv_pr.std():.3f}")
    print(f"        Recall    : {cv_rc.mean():.3f} ± {cv_rc.std():.3f}")

    # Feature importance
    print(f"\n      Feature importance:")
    for name, imp in sorted(
        zip(FEATURE_COLS, rf.feature_importances_),
        key=lambda x: -x[1]
    )[:5]:
        print(f"        {name:<20} {imp:.3f}")

    # Save
    with open(MODEL_RF,  'wb') as f: pickle.dump(rf,       f)
    with open(MODEL_IF,  'wb') as f: pickle.dump(iso,      f)
    with open(ENCODERS,  'wb') as f: pickle.dump(encoders, f)
    print(f"\n      Models saved.")
    return rf, iso, encoders

def predict(alert_raw, rf, iso, encoders):
    feat     = build_features(alert_raw, encoders)
    X        = np.array([[feat[c] for c in FEATURE_COLS]])

    rf_pred  = rf.predict(X)[0]
    rf_proba = rf.predict_proba(X)[0]
    rf_conf  = int(max(rf_proba) * 100)
    rf_label = "TP" if rf_pred == 1 else "FP"

    if_score = iso.decision_function(X)[0]
    if_pred  = iso.predict(X)[0]
    if_label = "TP" if if_pred == -1 else "FP"

    if rf_label == if_label:
        verdict    = rf_label
        confidence = min(rf_conf + 5, 99)
        method     = "both-agree"
    else:
        verdict    = rf_label
        confidence = max(rf_conf - 10, 50)
        method     = "rf-wins"

    return verdict, confidence, method, if_score

def live_monitor(rf, iso, encoders):
    print("\n" + "=" * 95)
    print("   LIVE CURATED ALERT MONITOR")
    print("   Hanya TRUE POSITIVE yang ditampilkan — FP otomatis disuppress")
    print("   Ctrl+C untuk stop dan lihat summary")
    print("=" * 95)
    print(f"\n{'Timestamp':<20} {'Rule':<6} {'Lvl':<4} {'Conf':<5} "
          f"{'Method':<12} {'Agent':<18} {'Description'}")
    print("-" * 95)

    seen_ids = set()
    stats    = {'total': 0, 'tp': 0, 'fp': 0}

    # Seed seen IDs dari alert lama
    with open(ALERTS_LOG) as f:
        for line in f:
            try:
                seen_ids.add(json.loads(line).get('id'))
            except:
                pass

    print(f"   [*] Seeded {len(seen_ids)} existing alerts — monitoring new alerts...\n")

    while True:
        try:
            with open(ALERTS_LOG) as f:
                for line in f:
                    try:
                        raw      = json.loads(line)
                        alert_id = raw.get('id')
                        if alert_id in seen_ids:
                            continue
                        seen_ids.add(alert_id)
                        stats['total'] += 1

                        verdict, conf, method, if_score = predict(raw, rf, iso, encoders)

                        rule  = raw.get('rule', {})
                        agent = raw.get('agent', {})
                        data  = raw.get('data', {})
                        ts    = raw.get('timestamp', '')[:19]
                        desc  = rule.get('description', '')[:38]
                        level = rule.get('level', 0)

                        # Log semua ke file
                        with open(CURATED_LOG, 'a') as log:
                            log.write(json.dumps({
                                'timestamp':   ts,
                                'rule_id':     rule.get('id'),
                                'level':       level,
                                'description': rule.get('description'),
                                'agent':       agent.get('name'),
                                'srcip':       data.get('srcip', ''),
                                'verdict':     verdict,
                                'confidence':  conf,
                                'method':      method,
                                'suppressed':  verdict == 'FP'
                            }) + '\n')

                        if verdict == 'FP':
                            stats['fp'] += 1
                            continue  # suppress — tidak tampil di terminal

                        # Hanya TP yang tampil
                        stats['tp'] += 1

                        RED    = "\033[91m"
                        YELLOW = "\033[93m"
                        CYAN   = "\033[96m"
                        BOLD   = "\033[1m"
                        RESET  = "\033[0m"

                        if level >= 10:
                            color = RED + BOLD
                        elif level >= 7:
                            color = YELLOW
                        else:
                            color = CYAN

                        print(
                            f"{color}{ts:<20}{RESET} "
                            f"{color}{rule.get('id','?'):<6}{RESET} "
                            f"{level:<4} {conf}%  "
                            f"{method:<12} "
                            f"{agent.get('name','?'):<18} "
                            f"{desc}"
                        )

                    except:
                        pass

            time.sleep(2)

        except KeyboardInterrupt:
            total = stats['total']
            print(f"\n{'='*60}")
            print(f"   SESSION SUMMARY")
            print(f"{'='*60}")
            if total > 0:
                print(f"   Total alerts masuk    : {total}")
                print(f"   FP disuppress         : {stats['fp']} ({stats['fp']/total*100:.1f}%)")
                print(f"   TP ditampilkan        : {stats['tp']} ({stats['tp']/total*100:.1f}%)")
                print(f"   Noise reduction       : {stats['fp']/total*100:.1f}%")
            print(f"   Curated log           : {CURATED_LOG}")
            print(f"{'='*60}")
            break

if __name__ == "__main__":
    rf, iso, encoders = train()
    live_monitor(rf, iso, encoders)
