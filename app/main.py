import sys
import os
from app import load_rules
from app import is_valid_bot
from app import decode_log_line
from app import analyze_log_fields
from app.log_decoder import clean

def main():
    """
    Main entry point for the NGINX access log analyzer.

    This function:
    1. Validates command-line arguments: expects a log file, rules file, and output file path.
    2. Loads regex-based detection rules from a JSON file.
    3. Processes the access log line-by-line:
        - Skips unparsable lines
        - Skips requests from verified bot IPs based on reverse and forward DNS validation
        - Applies regex rules to the URL field of each request
        - Writes matched lines (with line number and rule ID) to the output file

    Usage:
        python -m app.main <nginx_access_log> <regex_rules_file> <output_file>

    Expected file formats:
        - Log file: Standard NGINX combined log format
        - Rules file: JSON array of objects with 'id' and 'pattern'
        - Output file: Text file containing line number, rule ID, and decoded log entry

    Output:
        - Writes one line per detected match to the output file in the format:
          <line_number> <rule_id> <decoded_log_line>
    """
    if len(sys.argv) != 4:
        print("Usage: python -m app.main <nginx_access_log> <regex_rules_file> <output_file>")
        sys.exit(1)

    log_path = sys.argv[1]
    rules_path = sys.argv[2]
    output_path = sys.argv[3]

    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        sys.exit(1)

    if not os.path.exists(rules_path):
        print(f"Rules file not found: {rules_path}")
        sys.exit(1)

    rules = load_rules(rules_path)
    print(f"Loaded {len(rules)} rules from {rules_path}")

    with open(log_path, 'r', encoding='utf-8', errors='replace') as logfile, \
         open(output_path, 'w', encoding='utf-8') as outfile:

        for lineno, line in enumerate(logfile, 1):
            linedecoded, fields = decode_log_line(line)
            
            if not linedecoded:
                # outfile.write(f"{lineno} unparseable {clean(line)}\n")
                continue  # skip lines that couldn't be parsed

            ip = fields.get('ip', '-')
            ua = fields.get('user_agent', '-')
            if is_valid_bot(ip, ua):
                # outfile.write(f"{lineno} valid-bot {linedecoded}\n")
                continue  # skip processing of known good bots

            attack = analyze_log_fields(fields, rules)
            if attack:
                outfile.write(f"{lineno} {attack} {linedecoded}\n")
            #     continue
            
            # outfile.write(f"{lineno} benign {linedecoded}\n")

    print(f"\n[✓] Done. Matched lines written to: {output_path}")

if __name__ == "__main__":
    main()
