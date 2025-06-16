import sys
import os
from app import load_rules
from app import is_valid_bot
from app import decode_log_line
from app import analyze_log_fields
from app.log_decoder import clean

def main():
    """
    Main entry point for the LogSleuth NGINX access log analyzer.

    This function performs the following steps:
    1. Validates the command-line arguments: expects a log file, a JSON rules file, and an output file path.
    2. Loads detection rules (regex patterns with identifiers) from the provided rules file.
    3. Processes the access log file line by line:
        - Ignores unparsable lines.
        - Skips requests from verified bots using reverse and forward DNS checks.
        - Applies regex rules to the URL field of each valid request.
        - Writes matched lines to the output file, including the line number and matching rule ID.

    Usage:
        python -m app.main <nginx_access_log> <regex_rules_file> <output_file>

    File format expectations:
        - Log file: Standard NGINX combined access log format.
        - Rules file: JSON array of objects, each with:
            - 'id': A unique identifier string.
            - 'pattern': A regular expression string.
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
                continue  # skip lines that couldn't be parsed

            ip = fields.get('ip', '-')
            ua = fields.get('user_agent', '-')
            if is_valid_bot(ip, ua):
                continue  # skip processing of known good bots

            attack = analyze_log_fields(fields, rules)
            if attack:
                outfile.write(f"{lineno} {attack} {linedecoded}\n")

    print(f"\n[✅] Done. Matched lines written to: {output_path}")

if __name__ == "__main__":
    main()
