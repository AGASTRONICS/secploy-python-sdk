import os
from dotenv import load_dotenv, set_key, find_dotenv

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)


def autox_set_env(key: str, value: str, path: str = dotenv_path):
    if not key or value is None:
        raise ValueError("Both key and value must be provided.")
    set_key(path, key, value)


def autox_get_env(key: str) -> str | None:
    if not key:
        raise ValueError("Key must be provided.")
    return os.getenv(key)
