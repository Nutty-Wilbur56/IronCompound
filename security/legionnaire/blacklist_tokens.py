import json
import threading
import os

GULAG_FILE = 'administration/gulag.json'
# blacklist file

gulag_lock = threading.Lock()
# the blacklist lock
blacklist = set()

def load_blacklist():
    # loading of blacklist upon server start
    global blacklist
    if os.path.exists(GULAG_FILE):
        # check to see if black list file exists
        with open(GULAG_FILE, 'r') as gugfile:
            with gulag_lock:
                blacklist = json.load(gugfile)

def save_blacklist():
    # saving blacklist to enable blacklist to be persistent
    with open(GULAG_FILE, 'w') as gugfile:
        with gulag_lock:
            json.dump(list(blacklist), gugfile)

def check_token_status(token: str) -> bool:
    # checking to see if session token exists in the server's blacklist
    with gulag_lock:
        return token in blacklist

def blacklist_token(token: str):
    """called when user of session violates Iron Compound's security
    token is taken in, added to blacklist and then save black list function is called, in order
    to make blacklist persistent.
    """
    with gulag_lock:
        blacklist.add(token)
        save_blacklist()