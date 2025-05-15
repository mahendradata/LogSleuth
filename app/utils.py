import json
import re

def load_rules(filepath):
    """
    Load and compile detection rules from a JSON file.

    The JSON file must contain a list of rule objects, where each rule is a
    dictionary with the following structure:

        {
            "id": "unique-rule-id",
            "description": "Short explanation of the rule",
            "pattern": "regex pattern string"
        }

    This function reads the rules, compiles the 'pattern' string into a
    regular expression object (case-insensitive), and adds a new key 'compiled'
    to each rule dictionary.

    Args:
        filepath (str): Path to the JSON file containing the rules.

    Returns:
        list: A list of rule dictionaries, each with an added 'compiled' key
              containing the compiled regex object.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        rules = json.load(f)

    for rule in rules:
        # Compile to ensure it's a valid regex
        rule['compiled'] = re.compile(rule['pattern'], re.IGNORECASE)

    return rules
