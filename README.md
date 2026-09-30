# Error Message Linguistics Analyzer (EMLA)

EMLA is a security analysis software suite designed to crawl web applications, trigger non-destructive error states, detect sensitive information leakage (such as stack traces, database errors, framework debug pages, and internal filesystem paths), and compute a standardized **Direct Information Leakage Risk Score**.

---

## 🖥️ Interactive Software Mode (DriftSentry Style)

Simply run `emla` or `python3 -m emla.cli` without arguments to launch the **Interactive Software Suite Shell**:

```bash
emla
```

```
 ███████╗███╗   ███╗██╗      █████╗ 
 ██╔════╝████╗ ████║██║     ██╔══██╗
 █████╗  ██╔████╔██║██║     ███████║
 ██╔══╝  ██║╚██╔╝██║██║     ██╔══██╗
 ███████╗██║ ╚═╝ ██║███████╗██║  ██║
 ╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝

 🛡️ ERROR MESSAGE LINGUISTICS ANALYZER | v0.1.0 [Kali Linux Certified]

 Interactive Mode Active. Type 'help' for command list, 'exit' or 'q' to quit.

emla (127.0.0.1:8888) > scan
```

### Interactive Shell Commands
- `target <URL>` — Set the active target URL
- `scan [URL]` — Run vulnerability crawl & error leakage scan
- `report [filename]` — Display formatted JSON report
- `clear` — Clear screen and redraw banner
- `help` — Show command menu
- `exit` or `q` — Exit EMLA

---

## 🚀 Installation on Kali Linux

```bash
# 1. Navigate to project folder & copy to Kali home:
cp -r /media/sf_Share ~/emla_project
cd ~/emla_project

# 2. Activate Python Virtual Environment:
python3 -m venv venv
source venv/bin/activate

# 3. Install Dependencies & EMLA Package:
pip install -r requirements.txt
pip install -e .
```

---

## ⚡ Direct Command Line Usage

### 1. Interactive Shell Mode (Default)
```bash
emla
```

### 2. Direct Target Scan
```bash
emla -t http://target-app.local
```

### 3. Single URL Scan
```bash
emla -t http://target-app.local/api/login --single-url
```

### 4. Run Verification Suite against Mock Server
```bash
python3 generate_e2e_report.py
```
