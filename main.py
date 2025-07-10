import argparse
import logging
import yaml
import json
from jsonschema import validate, ValidationError, SchemaError
from deepdiff import DeepDiff

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes system configuration and suggests hardening measures.")
    parser.add_argument("config_file", help="Path to the system configuration file (YAML).")
    parser.add_argument("baseline_file", help="Path to the security baseline file (JSON Schema).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def load_config(config_file):
    """
    Loads the system configuration from a YAML file.
    Handles file not found and YAML parsing errors.
    """
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        return config_data
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise

def load_baseline(baseline_file):
    """
    Loads the security baseline from a JSON Schema file.
    Handles file not found and JSON parsing errors.
    """
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
        return baseline_data
    except FileNotFoundError:
        logging.error(f"Baseline file not found: {baseline_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        raise

def validate_config(config_data, baseline_data):
    """
    Validates the configuration data against the JSON Schema baseline.
    Returns True if valid, False otherwise. Logs validation errors.
    """
    try:
        validate(instance=config_data, schema=baseline_data)
        return True
    except ValidationError as e:
        logging.error(f"Validation error: {e.message} at {e.json_path}")
        return False
    except SchemaError as e:
        logging.error(f"Schema error: {e}")
        return False

def diff_config(config_data, baseline_data):
    """
    Compares the configuration data against the baseline data using DeepDiff.
    Returns a dictionary of differences.
    """
    try:
        diff = DeepDiff(config_data, baseline_data, ignore_order=True)
        return diff
    except Exception as e:
        logging.error(f"Error during diff: {e}")
        raise

def generate_report(diff, baseline_data):
     """
     Generates a report of non-compliance based on the differences found.
     Includes remediation recommendations from the baseline rules (if available).
     """
     report = []
     if diff:
        for key, changes in diff.items():
            if key == 'values_changed':
                for item, value in changes.items():
                    item_path = item.split('[')[1].split(']')[0].split("']['")
                    recommendation = find_recommendation(baseline_data, item_path)
                    severity = find_severity(baseline_data, item_path)

                    report.append({
                        "property": item,
                        "old_value": value['old_value'],
                        "new_value": value['new_value'],
                        "recommendation": recommendation,
                        "severity": severity
                    })
     return report

def find_recommendation(baseline_data, item_path):
    """
    Finds the remediation recommendation in the baseline data for a given property path.
    """
    current = baseline_data
    try:
        for part in item_path:
            current = current['properties'][part]
        if 'recommendation' in current:
            return current['recommendation']
        else:
             return "No specific recommendation available."
    except (KeyError, TypeError):
        return "No specific recommendation available."

def find_severity(baseline_data, item_path):
    """
    Finds the severity of the configuration item in the baseline data.
    """
    current = baseline_data
    try:
        for part in item_path:
            current = current['properties'][part]

        if 'severity' in current:
            return current['severity']
        else:
            return "Medium"
    except (KeyError, TypeError):
        return "Medium"

def print_report(report):
    """
    Prints the non-compliance report to the console.
    """
    if report:
        print("Non-Compliance Report:")
        for item in report:
            print(f"  Property: {item['property']}")
            print(f"    Old Value: {item['old_value']}")
            print(f"    New Value: {item['new_value']}")
            print(f"    Recommendation: {item['recommendation']}")
            print(f"    Severity: {item['severity']}")
            print("-" * 30)
    else:
        print("No non-compliance issues found.")

def main():
    """
    Main function to orchestrate the configuration analysis and reporting.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Load configuration and baseline
        config_data = load_config(args.config_file)
        baseline_data = load_baseline(args.baseline_file)

        # Validate configuration against baseline
        if not validate_config(config_data, baseline_data):
            logging.warning("Configuration does not conform to the baseline.")

        # Diff configuration against baseline
        diff = diff_config(config_data, baseline_data)

        # Generate and print the report
        report = generate_report(diff, baseline_data)
        print_report(report)


    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)

if __name__ == "__main__":
     # Example Usage (replace with actual file paths):
    # Create sample YAML config file (config.yaml)
    # with open("config.yaml", "w") as f:
    #     f.write("""
    # server:
    #     hostname: example.com
    #     port: 8080
    #     security:
    #         ssl_enabled: false
    #         tls_version: "1.2"
    # """)

    # Create sample JSON Schema baseline (baseline.json)
    # with open("baseline.json", "w") as f:
    #     f.write("""
    # {
    #     "$schema": "http://json-schema.org/draft-07/schema#",
    #     "title": "Security Baseline",
    #     "type": "object",
    #     "properties": {
    #         "server": {
    #             "type": "object",
    #             "properties": {
    #                 "hostname": {
    #                     "type": "string"
    #                 },
    #                 "port": {
    #                     "type": "integer"
    #                 },
    #                 "security": {
    #                     "type": "object",
    #                     "properties": {
    #                         "ssl_enabled": {
    #                             "type": "boolean",
    #                             "recommendation": "Enable SSL to encrypt traffic.",
    #                             "severity": "High"
    #                         },
    #                         "tls_version": {
    #                             "type": "string",
    #                             "enum": ["1.3", "1.2"],
    #                             "recommendation": "Use TLS version 1.3 for enhanced security.",
    #                             "severity": "Medium"
    #                         }
    #                     },
    #                     "required": ["ssl_enabled", "tls_version"]
    #                 }
    #             },
    #             "required": ["hostname", "port", "security"]
    #         }
    #     },
    #     "required": ["server"]
    # }
    # """)

    #  To run:
    #  python main.py config.yaml baseline.json
    main()