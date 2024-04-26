import platform
import subprocess

from getmac import get_mac_address as gma


def get_device_info() -> tuple:
    mac_address = gma()
    serial_number = __get_serial_number()
    model = get_model()

    return serial_number, mac_address, model


def __get_serial_number():
    system = platform.system()
    if system == 'Windows':
        return __get_windows_serial_number()
    elif system == 'Linux':
        return __get_linux_serial_number()
    else:
        return None


def __get_windows_serial_number():
    try:
        result = subprocess.check_output(['wmic', 'bios', 'get', 'serialnumber'], text=True)
        lines = result.split('\n')
        serial_number = lines[2].strip()
        return serial_number
    except Exception as e:
        print(f"Chyba pri získavaní sériového čísla na Windows: {e}")
        return None


def __get_linux_serial_number():
    try:
        with open('/sys/class/dmi/id/product_serial', 'r') as file:
            serial_number = file.read().strip()
        return serial_number
    except Exception as e:
        print(f"Chyba pri získavaní sériového čísla na Linux: {e}")
        return None


def get_model():
    system = platform.system()
    if system == 'Windows':
        return __get_windows_model()
    elif system == 'Linux':
        return __get_linux_model()
    else:
        return None


def __get_windows_model():
    try:
        result = subprocess.check_output(['wmic', 'csproduct', 'get', 'name'], text=True)
        lines = result.split('\n')
        serial_number = lines[2].strip()
        return serial_number
    except Exception as e:
        print(f"Chyba pri získavaní modelu stroja na Windows: {e}")
        return None


def __get_linux_model():
    try:
        with open('/sys/class/dmi/id/product_name', 'r') as file:
            model = file.read().strip()
        return model
    except Exception as e:
        print(f"Chyba pri získavaní modelu na Linux: {e}")
        return None

def create_docker_secret(name, value):
    subprocess.run(["docker", "secret", "create", name, "-"], input=value.encode(), check=True)

if __name__ == '__main__':
    serial_number, mac_address, model = get_device_info()
    create_docker_secret("secret1", mac_address)
    create_docker_secret("secret2", serial_number)
    create_docker_secret("secret3", model)
    # Prečítanie obsahu .env súboru
    with open('.env', 'r') as file:
        content = file.read()

    # Nahrádzanie špecifických hodnôt
    #content = content.replace('<<serial_number>>', serial_number)
    #content = content.replace('<<mac_address>>', mac_address)
    #content = content.replace('<<model>>', model)

    # Zápis aktualizovaného obsahu späť do súboru
    with open('.env', 'w') as file:
        file.write(content)

