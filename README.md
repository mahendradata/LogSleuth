## 🧾 Log Analyzer for NGINX (with Bot Filtering and Regex Rules)

This tool analyzes NGINX access logs to detect potentially malicious patterns using regex-based rules. It supports decoding obfuscated payloads and filtering out valid bots using reverse+forward DNS checks.

---

### ✅ Usage (Command Line)

#### Run locally (Python)

```bash
python -m app.main <access_log_file> <rules_file.json> <output_file.log>
```

#### Example:

```bash
python -m app.main logs/sample_access.log rules/default_rules.json outputs/detected.log
```

---

### 📥 Input

* **Access log file** (`logs/sample_access.log`):
  Standard NGINX log format (combined).

* **Rules file** (`rules/default_rules.json`):
  JSON array of rules, each containing:

  ```json
  {
    "id": "xss-script-tag",
    "description": "Detect <script> injection",
    "pattern": "<script.*?>.*?</script>"
  }
  ```

---

### 📤 Output

* Lines matching a rule are written to the output file, e.g.:

```
15 xss-script-tag 192.168.1.1 - - [07/May/2025:12:01:52 +0700] "GET /index.php?q=<script>alert(1)</script> HTTP/1.1" 200 123 "-" "Mozilla" "-"
```

Each output line includes:

```
<line_number> <rule_id> <decoded_log_line>
```

---

## 🐳 Docker Compatibility

This project is Dockerized for easy deployment and analysis across environments.

### 🔧 Build and Run

#### 1. Build the Docker image:

```bash
docker compose build
```

#### 2. Run the analyzer:

```bash
docker compose run analyzer
```

### 📂 Volume Mappings

The container uses volume mounts to access external log/rule/output files:

```yaml
volumes:
  - ./logs:/logs         # Put your input log files here
  - ./rules:/rules       # Place your JSON rule files here
  - ./outputs:/outputs   # Output files are written here
```

#### Example Command (from `docker-compose.yml`):

```yaml
command: /logs/sample_access.log /rules/default_rules.json /outputs/default_rules.log
```

> You can override the command to analyze a different file:

```bash
docker-compose run analyzer /logs/another.log /rules/sql_rules.json /outputs/another_output.log
```

---

### 📦 Requirements

If you're running it without Docker, install dependencies:

```bash
pip install -r requirements.txt
```