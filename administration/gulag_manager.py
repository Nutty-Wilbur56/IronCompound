import json
import os
class GulagManager:
    # class is for managing clients that get sent to the gulag
    nkvd_file = 'gulag.json'

    @classmethod
    def load_path(cls):
        if os.path.exists(cls.nkvd_file):
            with open(cls.nkvd_file, 'r') as file:
                return json.load(file)
        return []

    @classmethod
    def send_to_gulag(cls, client_record):
        # blacklisting client
        data = cls.load_path()
        data.append(client_record)

        with open(cls.nkvd_file, 'w') as file:
            json.dump(data, file, indent=2)

    @classmethod
    def is_client_in_gulag(cls, token_or_ip):
        # checking if client exists in blacklist
        data = cls.load_path()
        return any(real['token'] == token_or_ip or real['ip'] == token_or_ip for real in data)