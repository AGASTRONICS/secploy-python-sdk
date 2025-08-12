# autox configuration loader

import yaml  # For YAML file handling
import json  # For JSON file handling
import os    # For path checks

def load_config(file_path):
    """Load configuration from YAML, JSON, CONF, or .autoxfile formats."""
    if not os.path.exists(file_path):
        print(f"Config file {file_path} not found. Using default configuration.")
        return {}

    extension = os.path.splitext(file_path)[1].lower()

    if extension in ['.yml', '.yaml']:
        with open(file_path, 'r') as file:
            try:
                config = yaml.safe_load(file)
                print("Loaded YAML configuration.")
                return config
            except yaml.YAMLError as e:
                print(f"Error loading YAML: {e}")
    elif extension == '.json':
        with open(file_path, 'r') as file:
            try:
                config = json.load(file)
                print("Loaded JSON configuration.")
                return config
            except json.JSONDecodeError as e:
                print(f"Error loading JSON: {e}")
    elif extension == '.conf':
        config = {}
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
        print("Loaded CONF configuration.")
        return config
    elif extension in ['.autox']:
        # Custom parsing logic for .autox formats (you can adjust this)
        config = {}
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
        print(f"Loaded {extension} configuration.")
        return config
    else:
        print(f"Unsupported config file format: {extension}")
        return {}