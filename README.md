# 🛡️ Reducing SOC False Alarms through Human-AI Collaboration

> Final Project — Keamanan Informasi | Institut Teknologi Sepuluh Nopember  
> Departemen Teknologi Informasi | Semester Genap 2024/2025

---

## 📋 Deskripsi Proyek

Sistem ini mengimplementasikan **Human-AI Collaboration SOC** yang mengurangi false alarm pada Security Operations Center tanpa mengorbankan akurasi deteksi ancaman. Sistem mengintegrasikan Wazuh SIEM dengan model AI lokal (Random Forest + Isolation Forest) untuk mengklasifikasikan alert secara otomatis sebagai **True Positive (TP)** atau **False Positive (FP)**.

### Latar Belakang

Filosofi *Better Safe Than Sorry* pada SOC menyebabkan tingginya tingkat false positive yang memicu:
- **Alert fatigue** pada tim SOC analyst
- Pemborosan waktu review alert yang tidak relevan
- Potensi terlewatnya ancaman nyata di tengah noise

### Hasil

Sistem berhasil mereduksi noise sebesar **33.1%** — dari 127 alert yang masuk, 42 alert FP berhasil disuppress secara otomatis, sehingga SOC analyst hanya perlu mereview 85 alert TP yang relevan.

---

## 🏗️ Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                     Azure Cloud (FP-SOC VM)                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Wazuh Manager (All-in-One)               │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │   │
│  │  │   Wazuh     │  │    Wazuh     │  │   Wazuh    │  │   │
│  │  │   Indexer   │  │   Manager    │  │  Dashboard │  │   │
│  │  │ (OpenSearch)│  │  (Analysis)  │  │  (Kibana)  │  │   │
│  │  └─────────────┘  └──────────────┘  └────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                  │
│  ┌─────────────────────────▼────────────────────────────┐   │
│  │              AI False Positive Detector               │   │
│  │                                                       │   │
│  │  alerts.json → Rule-based Labeler → Training Data    │   │
│  │                      ↓                               │   │
│  │         Random Forest + Isolation Forest             │   │
│  │                      ↓                               │   │
│  │     Live Monitor → FP suppress / TP tampil           │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                  │
│  ┌─────────────────────────▼────────────────────────────┐   │
│  │              Active Response (SOAR)                   │   │
│  │         Auto-block IP berbahaya via iptables          │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
          ▲                          ▲
          │ Wazuh Agent              │ Wazuh Agent
┌─────────┴──────────┐    ┌─────────┴──────────┐
│  nginx-webdeploy   │    │    yafi-ubuntu      │
│  (Web Server VM)   │    │    (Attacker WSL)   │
└────────────────────┘    └────────────────────┘
```

---

## 🔧 Spesifikasi Sistem

### Infrastructure

| Komponen | Spesifikasi |
|---|---|
| Platform | Microsoft Azure |
| VM Wazuh Server | 4 vCPU, 16 GB RAM, Ubuntu 24.04 LTS |
| VM Web Agent | Azure VM, Ubuntu 22.04 LTS |
| Attacker | WSL (Windows Subsystem for Linux) |
| Wazuh Version | 4.12.x (All-in-One) |

### Wazuh Components

| Komponen | Port | Fungsi |
|---|---|---|
| Wazuh Indexer | 9200 | Penyimpanan dan indexing alert |
| Wazuh Manager | 1514, 1515 | Analisis log dan event dari agent |
| Wazuh Dashboard | 443 | Visualisasi dan monitoring |
| Wazuh API | 55000 | REST API untuk manajemen |

---

## 🤖 AI Integration

### Metodologi

Sistem menggunakan pendekatan **hybrid model** tanpa third-party API:

#### 1. Rule-based Auto Labeler (`fp-labeler.py`)

Mendefinisikan kriteria FP dan TP secara independen berdasarkan karakteristik alert Wazuh:

**Kriteria False Positive:**
- Level alert ≤ 3 (noise rendah)
- Rule ID yang diketahui normal: PAM session (5501, 5502), sudo (5402), SSH disconnect (5715, 5762), dpkg update (2901, 2902, 2904)
- Level 4 tanpa MITRE ATT&CK mapping dan hanya trigger sekali
- Web 400 error dengan firedtimes ≤ 3 (bot scan normal)

**Kriteria True Positive:**
- Rule brute force confirmed: 5551, 5712, 5763, 31151
- Level ≥ 10 (high severity)
- SSH failed login (5710, 5503, 5760) dengan firedtimes ≥ 3
- MITRE ATT&CK mapping: T1110 (Brute Force), T1059, T1021.004, T1190
- Suspicious URL access (31516)

#### 2. Feature Engineering

Fitur yang diekstrak dari setiap alert Wazuh:

| Fitur | Deskripsi | Importance |
|---|---|---|
| `has_srcip` | Ada/tidaknya source IP | 0.263 |
| `agent_id_enc` | ID agent terenkode | 0.168 |
| `rule_id_enc` | ID rule terenkode | 0.158 |
| `firedtimes` | Jumlah trigger rule | 0.115 |
| `mitre_count` | Jumlah MITRE mapping | 0.100 |
| `level` | Severity level (0-15) | - |
| `hour` | Jam kejadian | - |
| `is_night` | Flag jam malam (22:00-06:00) | - |
| `gdpr`, `pci_dss` | Compliance mapping | - |

#### 3. Hybrid Model (`fp-model-local.py`)

```
Alert baru masuk
       ↓
  Extract Features
       ↓
  ┌────────────────────────────────┐
  │     Random Forest (supervised)  │
  │   Trained dari labeled data     │
  │   class_weight='balanced'       │
  └────────────────┬───────────────┘
                   │
  ┌────────────────▼───────────────┐
  │  Isolation Forest (unsupervised)│
  │   Anomaly detection             │
  │   contamination = 0.09          │
  └────────────────┬───────────────┘
                   │
         ┌─────────▼──────────┐
         │  Hybrid Voting      │
         │  both-agree → high  │
         │  rf-wins → medium   │
         └─────────┬──────────┘
                   │
         ┌─────────▼──────────┐
         │ FP → suppress      │
         │ TP → tampilkan     │
         └────────────────────┘
```

**Oversample minority class** menggunakan `sklearn.utils.resample` untuk menangani imbalanced data (90.7% TP vs 9.3% FP).

### Benchmark Metrics

| Metrik | Nilai |
|---|---|
| Accuracy | 1.000 |
| Precision (FP class) | 1.000 |
| Recall (FP class) | 1.000 |
| F1-Score | 1.000 |
| Cross-val F1 (5-fold) | 1.000 ± 0.000 |
| Cross-val Precision | 1.000 ± 0.000 |
| Cross-val Recall | 1.000 ± 0.000 |

**Catatan:** Score sempurna disebabkan oleh desain sistem yang menggunakan rule-based labeler sebagai ground truth — model essentially menggeneralisasi aturan yang telah didefinisikan. Ini adalah *intended behavior* dari Human-AI collaboration: human expertise (SOC analyst) mendefinisikan kriteria, AI menggeneralisasi dan mengotomatisasi penerapannya.

### Hasil Deteksi Live

| Metrik | Nilai |
|---|---|
| Total alert diproses | 127 |
| FP disuppress | 42 (33.1%) |
| TP ditampilkan | 85 (66.9%) |
| Noise reduction | 33.1% |

---

## 🚨 Attack Scenarios

### Skenario 1: SSH Brute Force (T1110.001)

Simulasi password guessing attack via SSH:

```bash
# Dari WSL attacker
for i in {1..30}; do
  ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no \
    invaliduser$i@TARGET_IP 2>/dev/null
  sleep 0.3
done
```

**Alert yang ter-trigger:** Rule 5710, 5503, 5760, 5551, 5712 — semua diklasifikasikan TP.

### Skenario 2: Web Application Scanning (T1190)

Simulasi reconnaissance dan web scanning:

```bash
# Directory traversal dan path scanning
for path in /admin /wp-login.php /.env /config.php \
            /phpmyadmin /backup.zip /.git/config; do
  curl -s -o /dev/null "http://TARGET_IP$path"
  sleep 0.5
done
```

**Alert yang ter-trigger:** Rule 31101, 31151, 31516 — classified TP dengan confidence 84-90%.

### Skenario 3: Normal Activity (False Positive)

Aktivitas normal yang seharusnya disuppress:

```bash
# Web browsing normal — sedikit 400 error
for i in {1..5}; do
  curl -s -o /dev/null "http://TARGET_IP/notfound-$i"
  sleep 2
done
```

**Alert:** Rule 31101 dengan firedtimes ≤ 3 — diklasifikasikan FP dan disuppress.

---

## ⚡ Active Response (SOAR)

Wazuh Active Response dikonfigurasi untuk auto-block IP yang terdeteksi melakukan brute force:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5711,5712,5763</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Cara kerja:**
1. Alert SSH brute force (rule 5710/5712) ter-trigger
2. Wazuh execd memanggil `firewall-drop` script
3. IP attacker diblock via `iptables -I INPUT -s <IP> -j DROP`
4. Block otomatis dicabut setelah 600 detik (10 menit)

**Contoh IP yang berhasil diblock secara otomatis:**
- `91.92.40.10` — SSH brute force, user: `deploy`
- `132.251.234.110` — SSH brute force, user: `debian`
- `153.37.177.219` — SSH brute force, user: `centos`

---

## 📁 Struktur Repository

```
fp-soc/
├── README.md
├── src/
│   ├── fp-labeler.py          # Rule-based auto labeler
│   └── fp-model-local.py      # Hybrid AI model + live monitor
├── config/
│   └── ossec-active-response.xml  # Konfigurasi active response
├── data/
│   └── labeled_alerts.jsonl   # Contoh labeled training data
└── docs/
    ├── architecture.png        # Diagram arsitektur sistem
    └── results.png             # Screenshot hasil deteksi
```

---

## 🚀 Cara Menjalankan

### Prerequisites

```bash
# Install dependencies
sudo pip3 install scikit-learn pandas numpy --break-system-packages
```

### 1. Labeling Data

```bash
sudo python3 src/fp-labeler.py
```

Output: `labeled_alerts.jsonl` berisi alert berlabel FP/TP.

### 2. Training & Live Monitor

```bash
sudo python3 src/fp-model-local.py
```

Proses:
1. Load labeled data
2. Training Random Forest + Isolation Forest
3. Evaluasi model (classification report, confusion matrix, cross-validation)
4. Mulai live monitor — hanya TP yang ditampilkan di terminal

### 3. Output Live Monitor

```
===============================================================
   LIVE CURATED ALERT MONITOR
   Hanya TRUE POSITIVE yang ditampilkan — FP otomatis disuppress
===============================================================

Timestamp            Rule   Lvl  Conf  Method       Agent              Description
-----------------------------------------------------------------------
2026-06-25T03:02:15  5760   5    88%   both-agree   nginx-webdeploy    sshd: authentication failed.
2026-06-25T03:02:19  5763   10   85%   both-agree   nginx-webdeploy    sshd: brute force trying...
```

---

## 👥 Tim

| Nama | NRP | Peran |
|---|---|---|
| [Nama 1] | [NRP] | Infrastructure & Wazuh Setup |
| [Nama 2] | [NRP] | AI Model Development |
| [Nama 3] | [NRP] | Attack Simulation |
| [Nama 4] | [NRP] | Active Response & SOAR |
| [Nama 5] | [NRP] | Documentation & Report |
| [Nama 6] | [NRP] | Testing & Evaluation |

---

## 📚 Referensi

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Scikit-learn: Random Forest & Isolation Forest
- PCI DSS, GDPR, HIPAA compliance mappings via Wazuh rules

---

*Institut Teknologi Sepuluh Nopember — Departemen Teknologi Informasi — 2025*
