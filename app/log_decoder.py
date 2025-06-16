import re
import codecs
import urllib.parse
import base64

# Regex for NGINX log format
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<extra>[^"]*)"'
)

def clean(text):
    """
    Sanitize log field text by escaping newlines and trimming whitespace.

    This function replaces newline characters with their escaped versions
    (e.g., '\n' → '\\n') and strips leading/trailing whitespace.

    Args:
        text (str): The input string to sanitize.

    Returns:
        str: A cleaned and safe string for output or analysis.
    """
    return text.replace('\n', '\\n').replace('\r', '\\r').strip()


def smart_decode(textori):
    """
    Decode obfuscated or encoded text from URLs or headers using layered decoding.

    This function attempts multiple decoding techniques to normalize text that
    may have been encoded or obfuscated. The steps include:
    1. Percent-decoding (handles both single and double encoded inputs).
    2. Interpreting Python-style byte escape sequences (e.g., \x41, \u1234).
    3. Optionally attempting Base64 decoding of the last URL segment if it appears valid.

    If Base64 decoding is successful, it appends a decoded string as metadata to the result.

    Args:
        textori (str): The original encoded string.

    Returns:
        str: The decoded string, potentially with base64-derived insight appended.
    """
    try:
        # Step 1: Percent-decode (handle single and double encoding)
        text = urllib.parse.unquote(textori)
        text = urllib.parse.unquote(text)

        # Step 2: Decode byte escape sequences like \x41
        if '\\x' in text or '\\u' in text:
            text = codecs.escape_decode(text.encode())[0].decode('utf-8', errors='replace')

        # Step 3: Try base64 decoding last URL path segment if it looks like base64
        last_part = text.split("/")[-1]
        if re.fullmatch(r'[A-Za-z0-9+/=]{8,}', last_part):  # crude base64 heuristic
            try:
                decoded_base64 = base64.b64decode(last_part, validate=False).decode('utf-8', errors='ignore')
                text += f"-base64:{decoded_base64}"  # append insight, don't overwrite
            except Exception:
                pass

        return text
    except Exception:
        return text


def decode_log_line(line):
    """
    Parse and decode a single NGINX access log line into structured components.

    This function matches the input log line against a predefined NGINX regex format,
    extracts relevant fields (IP, timestamp, method, URL, status, etc.), sanitizes
    them using `clean()`, and decodes selected fields using `smart_decode()` to
    uncover obfuscation or encoded payloads.

    Args:
        line (str): A raw log line string from the access log.

    Returns:
        tuple:
            - str: A reconstructed log line with cleaned and decoded fields.
            - dict: A dictionary of structured fields, or (None, None) if the line cannot be parsed.
    """
    match = log_pattern.match(line)
    if not match:
        return None, None  # No match, return None to indicate unparsable log line

    fields = match.groupdict()

    # Apply smart decoding to selected fields
    fields['ip'] = clean(fields['ip'])
    fields['time'] = clean(fields['time'])
    fields['method'] = clean(fields['method'])
    fields['url'] = clean(smart_decode(fields['url']))
    fields['protocol'] = clean(fields['protocol'])
    fields['status'] = clean(fields['status'])
    fields['size'] = clean(fields['size'])
    fields['referrer'] = clean(smart_decode(fields['referrer']))
    fields['user_agent'] = clean(fields['user_agent'])
    fields['extra'] = clean(fields['extra'])

    line = (
        f'{fields["ip"]} - - [{fields["time"]}] '
        f'"{fields["method"]} {fields["url"]} {fields["protocol"]}" '
        f'{fields["status"]} {fields["size"]} '
        f'"{fields["referrer"]}" "{fields["user_agent"]}" "{fields["extra"]}"'
    )

    return line, fields
