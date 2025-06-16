## 🧾 LogSleuth: NGINX Log Analyzer with Bot Filtering and Regex Detection

LogSleuth is a Python-based tool to analyze NGINX access logs and detect suspicious patterns using customizable regex-based rules. It includes:

* Decoding obfuscated payloads (e.g., URL-encoded, Base64).
* Skipping verified bots through reverse and forward DNS validation.
* Flexible rule configuration via JSON.

---

### ✅ Command-Line Usage

#### Run Locally with Python

```bash
python -m app.main <access_log_file> <rules_file.json> <output_file.log>
```

#### Example

```bash
python -m app.main logs/sample_access.log rules/default_rules.json outputs/detected.log
```

---

### 📥 Input Format

#### Access Log File

* Format: Standard NGINX **combined** log format.

#### Rules File (JSON)

Each rule must be an object containing:

```json
{
  "id": "xss-script-tag",
  "description": "Detect <script> injection",
  "pattern": "<script.*?>.*?</script>"
}
```

At runtime, each `pattern` will be compiled as a regular expression.

---

### 📤 Output Format

Detected lines are written to the output file as:

```
<line_number> <rule_id> <decoded_log_line>
```

Example output:

```
15 xss-script-tag 192.168.1.1 - - [07/May/2025:12:01:52 +0700] "GET /index.php?q=<script>alert(1)</script> HTTP/1.1" 200 123 "-" "Mozilla" "-"
```

---

## 🐳 Docker Support

Run the analyzer in a containerized environment with ease.

### 🔧 Build and Run

#### Step 1: Build the Docker image

```bash
docker compose build
```

#### Step 2: Run the analyzer

```bash
docker compose run analyzer
```

---

### 📂 Volume Mappings

The Docker container expects logs, rules, and outputs to be placed in mounted folders:

```yaml
volumes:
  - ./logs:/logs         # Input log files
  - ./rules:/rules       # Regex rules in JSON format
  - ./outputs:/outputs   # Output files
```

#### Docker Compose Command Example

```yaml
command: /logs/sample_access.log /rules/default_rules.json /outputs/detected.log
```

Override the default command with:

```bash
docker compose run analyzer /logs/another.log /rules/sql_rules.json /outputs/result.log
```

---

### 📦 Requirements

To run without Docker, install dependencies via:

```bash
pip install -r requirements.txt
```