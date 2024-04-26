def get_secret_value(name: str, default_value: str) -> str:
    secret_path = f'/run/secrets/{name}'
    try:
        with open(secret_path, 'r') as secret_file:
            secret_value = secret_file.read().strip()
        return secret_value
    except IOError:
        return default_value
