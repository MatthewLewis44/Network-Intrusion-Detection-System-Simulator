## IDS-Simulator Project Summary

### Project Overview
**IDS-Simulator** is a complete intrusion detection system (IDS) simulator that generates synthetic network traffic, detects anomalies using rule-based and machine-learning methods, and serves a live dashboard to visualize threats. It combines packet simulation, statistical analysis, ML anomaly detection, and a web UI into one integrated system.

---

### Architecture & File Structure

```
IDS-Simulator/
├── ids_simulator.py           # Packet generator (80% normal / 20% malicious)
├── parse_logs.py              # CSV parser, rule/ML detection, alerting, CLI orchestrator
├── plot_utils.py              # Safe Matplotlib plotting (anomaly over time)
├── app.py                     # FastAPI web server (endpoints + dashboard)
├── templates/
│   └── dashboard.html         # Jinja2 HTML UI (alerts table, plot, generate button)
├── static/                    # Static file serving (generated PNGs, CSS)
├── tests/
│   └── test_detection.py      # Unit tests for detection logic
├── .github/workflows/
│   └── ci.yml                 # GitHub Actions CI (pytest on push/PR)
├── Dockerfile                 # Container image (alpine Python 3.10)
├── requirements.txt           # Python dependencies
├── network_logs.csv           # Generated packet log (100 rows)
└── app_fixed.py               # Backup of working app.py
```

---

### Core Components & How They Work

#### 1. **ids_simulator.py** — Packet Generator
**Purpose:** Create synthetic network traffic.

**How it works:**
- Generates 100 packets: 80 normal, 20 malicious.
- Each packet has: timestamp, src_ip, dst_ip, protocol (TCP/UDP/ICMP), port, payload_size, is_malicious flag.
- Malicious packets have large payloads (1000–48000 bytes) and unusual ports (>1024 or 0).
- Saves to `network_logs.csv`.

**Usage:**
```bash
python ids_simulator.py  # writes network_logs.csv
```

---

#### 2. **parse_logs.py** — Parser, Detectors & CLI Orchestrator
**Purpose:** Parse logs, run detections, and provide CLI for full pipeline.

**Key functions:**

- **`parse_network_logs(filepath)`**
  - Reads `network_logs.csv` into a pandas DataFrame.
  - Parses timestamps, sorts by time.
  - Adds `minute` column (for time-series aggregation) and `packets_per_minute`.
  - Prints first 10 rows and summary stats.

- **`detect_anomalies(df, payload_threshold, port_threshold, rate_threshold)`**
  - Rule-based detection.
  - Flags packets with:
    - payload_size > 1000 bytes, OR
    - port < 1024 or > 65535, OR
    - packets_per_minute > 50.
  - Adds `detected_anomaly` and `anomaly_reason` columns.

- **`ml_isolation_forest(df, contamination='auto')`**
  - Unsupervised ML detection using scikit-learn's IsolationForest.
  - Trains on features: port, payload_size, packets_per_minute.
  - Adds `ml_detected` column.
  - Prints accuracy and classification report.

- **`alert_on_detections(df)`**
  - Prints alerts for each detected anomaly in format:
    ```
    ALERT: Potential intrusion from 192.168.X.X at 2025-11-23 14:33:36.730420 - Type: rule
    ```
  - Prints total alert count.

- **`plot_anomalies(df, outpath)`**
  - Generates a line plot of anomaly counts over time.
  - Groups by minute, plots with matplotlib.
  - Saves to `outpath` (e.g., `static/anomalies.png`).
  - Shows "No anomalies detected" placeholder if none found.

- **`main()`** — CLI orchestrator
  - Supports argparse flags:
    - `--num_packets 100` (default)
    - `--mode rule|ml|both` (detection mode)
    - `--payload_threshold 1000`
    - `--port_threshold 1024`
    - `--rate_threshold 50`
  - Auto-generates logs if missing, runs detection, prints alerts.

**Usage:**
```bash
python parse_logs.py --num_packets 200 --mode both --payload_threshold 500
```

---

#### 3. **plot_utils.py** — Safe Plotting
**Purpose:** Generate PNG anomaly plots without blocking the server.

**Key function:**

- **`safe_plot_anomalies(df, outpath)`**
  - Uses non-interactive Matplotlib backend (`Agg`).
  - Handles missing/empty DataFrames gracefully (renders placeholder).
  - Groups detected anomalies by minute, plots counts.
  - Atomically writes to `outpath` (write to temp, then move).
  - Raises informative errors if matplotlib missing.

**Usage:**
```python
from plot_utils import safe_plot_anomalies
safe_plot_anomalies(df, 'static/anomalies.png')
```

---

#### 4. **app.py** — FastAPI Web Server
**Purpose:** Expose IDS functionality via HTTP API and web dashboard.

**Architecture:**
- Lazy imports `parse_logs` inside endpoints (avoids heavy side-effects at server startup).
- Mounts static files at `/static` (serves PNGs, CSS, JS).
- Renders Jinja2 templates for HTML UI.
- CORS enabled (allow all origins).

**Endpoints:**

| Route | Method | Purpose |
|-------|--------|---------|
| `/logs` | GET | Returns all parsed packets as JSON |
| `/alerts` | GET | Runs detection, returns detected anomalies as JSON |
| `/generate-plot` | GET | Runs full pipeline (parse → detect → plot), creates `static/anomalies.png`, returns JSON |
| `/anomalies.png` | GET | Redirects to `/static/anomalies.png` (legacy URL support) |
| `/anomalies-file` | GET | Serves PNG directly with MIME type image/png |
| `/dashboard` | GET | Renders HTML dashboard (if `templates/dashboard.html` exists, else minimal fallback) |

**Key behaviors:**
- On first `/dashboard` load: if `static/anomalies.png` missing, auto-generates it.
- `/generate-plot` calls `safe_plot_anomalies()` directly (no parse_logs detour).
- All endpoints catch exceptions and return 500 with detail (for debugging).

**Usage:**
```bash
uvicorn app:app --reload --log-level debug
# Open http://127.0.0.1:8000/dashboard
```

---

#### 5. **templates/dashboard.html** — Web UI
**Purpose:** Interactive dashboard for monitoring alerts and anomalies.

**Features:**
- **Alerts Table**: Dynamically fetched from `/alerts` every 10 seconds.
  - Columns: Time, Source IP, Reason (rule/ml).
  - Displays "No alerts" if empty.

- **Generate Plot Button**: Calls `/generate-plot`, caches new PNG with timestamp to avoid stale browser cache.

- **Anomaly Plot Image**: References `/static/anomalies.png`, refreshes after plot generation.

- **Refresh Button**: Manually re-fetch alerts (useful for testing).

**Client-side JS:**
- Auto-refresh alerts every 10s.
- Cache-busting on plot generation: `img.src = path + '?ts=' + Date.now()`.

---

#### 6. **Dockerfile** — Container Image
**Purpose:** Package the app for deployment.

**Setup:**
- Base: `python:3.10-slim`
- Installs: `build-essential`, `libfreetype6-dev`, `libpng-dev`, `pkg-config` (for Matplotlib on Linux).
- Copies `requirements.txt` → installs deps.
- Copies `static/` folder and all app code.
- Exposes port 8000.
- Runs: `uvicorn app:app --host 0.0.0.0 --port 8000`.

**Usage:**
```bash
docker build -t ids-simulator:latest .
docker run -p 8000:8000 ids-simulator:latest
```

---

#### 7. **requirements.txt** — Dependencies
```
fastapi
uvicorn[standard]
jinja2
pandas
scikit-learn
matplotlib
pytest
```

---

#### 8. **tests/test_detection.py** — Unit Tests
**Purpose:** Validate detection logic.

**Tests:**
- `test_detect_anomalies_payload_and_port()`: Verify rule-based detection flags correct rows.
- `test_ml_isolation_forest_smoke()`: Smoke test for ML detection (skipped if scikit-learn missing).

**Run:**
```bash
pytest tests/test_detection.py -v
```

---

#### 9. **.github/workflows/ci.yml** — CI/CD
**Purpose:** Auto-run tests on push/PR.

**Actions:**
- Install Python 3.10, dependencies, run `pytest`.

---

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Request                             │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────┐
    │   app.py        │ (FastAPI server)
    └────────┬────────┘
             │
      ┌──────┴───────┬──────────────┬─────────────┐
      │              │              │             │
      ▼              ▼              ▼             ▼
   /logs       /alerts         /generate-plot  /dashboard
   (JSON)      (JSON)         (PNG + JSON)     (HTML)
      │         │ │              │              │
      │         │ │              ▼              ▼
      │         │ └────────────────────────────────┐
      │         │                                  ▼
      │         │          ┌────────────────────────────────────┐
      │         │          │  parse_logs.py                     │
      │         │          ├────────────────────────────────────┤
      │         │          │ 1. Parse network_logs.csv          │
      │         │          │ 2. Detect (rules + ML)             │
      │         │          │ 3. Alert on anomalies              │
      │         │          │ 4. Call plot_utils                 │
      │         │          └────────┬─────────────────────────────┘
      │         │                   │
      │         │                   ▼
      │         │          ┌────────────────────────┐
      │         │          │  plot_utils.py         │
      │         │          ├────────────────────────┤
      │         │          │ Generate Matplotlib    │
      │         │          │ anomalies.png          │
      │         │          └────────┬────────────────┘
      │         │                   │
      │         ▼                   ▼
      └─────────────────────────────┘
                  │
                  ▼
        ┌──────────────────────┐
        │  /static/            │
        ├──────────────────────┤
        │ anomalies.png        │
        │ test_plot.png        │
        │ [other assets]       │
        └──────────────────────┘
```

---

### Example Workflows

**Workflow 1: Generate Logs & Run Detections Locally**
```bash
# 1. Generate synthetic traffic
python ids_simulator.py

# 2. Parse, detect, plot, alert (CLI)
python parse_logs.py --num_packets 100 --mode both
```

**Workflow 2: Web Dashboard**
```bash
# 1. Start server
uvicorn app:app --reload

# 2. Open browser
start http://127.0.0.1:8000/dashboard

# 3. Click "Generate Plot" → refreshes anomalies.png and alerts table
```

**Workflow 3: API Consumption**
```bash
# Get all logs
curl http://127.0.0.1:8000/logs

# Get current alerts
curl http://127.0.0.1:8000/alerts

# Generate new plot
curl http://127.0.0.1:8000/generate-plot

# Download plot PNG
curl http://127.0.0.1:8000/static/anomalies.png -o plot.png
```

**Workflow 4: Docker Deployment**
```bash
# Build image
docker build -t ids-simulator:latest .

# Run container
docker run -p 8000:8000 ids-simulator:latest

# Access from host
curl http://127.0.0.1:8000/dashboard
```

---
