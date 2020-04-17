"""
<filename>.py

Author: Desmond Tan
"""

#################
# Imports
#################

from imports import *


#################
# Constants and Global variables
#################

DATABASE_FILE = 'file_metadata.sqlite3'
VIRUS_TOTAL_API = r'https://www.virustotal.com/vtapi/v2/file/report'
VIRUS_TOTAL_APIKEY = '16a7b99591f93d9877c5f26525b425ff3ba50692a62cd516810880ad75e0bbce'

WORKER_LIMIT = 3
YARA_RULES_FOLDER = 'yara_rules'

filescan_running = False
yarascan_running = False


#################
# Functions
#################

def init_db():
    if not os.path.isfile(DATABASE_FILE):
        import create_db


def get_db():
    """
    Gets a db object to query
    :return: a db object
    """

    db = sqlite3.connect(DATABASE_FILE)
    db.row_factory = sqlite3.Row
    return db


def extract_file_data(file_data):
    """
    extracts the fields from file_data to a dictionary, probably a better way to do this
    :param file_data: db query object
    :return: extracted fields in a dictionary
    """
    temp = {
        'file_id': file_data['file_id'],
        'hostname': file_data['hostname'],
        'filename': file_data['filename'],
        'root': file_data['root'],
        'hashed': file_data['hashed'],
        'file_type': file_data['file_type'],
        'file_size': file_data['file_size']
    }
    return temp


def filescan_handler(pending_hashes):
    """
    Thread handler for scanning on virus total
    :param pending_hashes: a set object containing all the unique hashes that does not exist in the database
    :return: None
    """
    global filescan_running

    hash_queue = Queue()

    for hash in pending_hashes:
        hash_queue.put(hash)

    for worker in range(WORKER_LIMIT):
        thread = Thread(target=scan_file_threaded, args=(hash_queue, ))
        thread.start()

    hash_queue.join()
    print 'file scan complete'
    filescan_running = False


def scan_file_threaded(hash_queue):
    """
    A handy dandy worker thread function that gets the job from a queue
    :param hash_queue: a queue of all the hashes
    :return: None
    """
    while not hash_queue.empty():
        hash = str(hash_queue.get()[0])

        params = {
            'apikey': VIRUS_TOTAL_APIKEY,
            'resource': hash
        }
        response = requests.get(VIRUS_TOTAL_API, params=params)

        if response.status_code == 200 and response.json()["response_code"] == 1:
            vt_results = json.dumps(response.json())

            db = get_db()
            db.execute('INSERT INTO VTOTAL_RESULTS (hashed, vtotal_results) VALUES(?, ?)', (hash, vt_results))
            db.commit()

        time.sleep(15) # to prevent flooding the virus total api
        hash_queue.task_done()


def compile_yara_rules():
    rules = os.listdir(YARA_RULES_FOLDER)
    filepaths = {}
    for index, rule in enumerate(rules):
        filepaths['namespace'+str(index)] = os.path.join(YARA_RULES_FOLDER, rule)

    rules = yara.compile(filepaths=filepaths)
    return rules


def extract_rules(matches):
    rules = []
    for _, value in matches.items():
        rules.append(value[0]['rule'])
    return rules


def yara_scan(pending_hashes, upload_folder):
    global yarascan_running

    rules = compile_yara_rules()

    for hashed in pending_hashes:
        filepath = os.path.join(upload_folder, hashed)
        with open(filepath, 'r') as bin_file:
            matches = rules.match(data=bin_file.read())

        matched_rules = extract_rules(matches)

        db = get_db()
        yara_results = db.execute('SELECT * FROM YARA_RESULTS WHERE hashed=?', (hashed,)).fetchall()

        if yara_results != []:
            db.execute('UPDATE YARA_RESULTS SET yara_results=? WHERE hashed=?', (json.dumps(matched_rules), hashed))
        else:
            db.execute('INSERT INTO YARA_RESULTS (hashed, yara_results) VALUES(?, ?)',
                       (hashed, json.dumps(matched_rules)))
        db.commit()

    print 'yara scan complete'
    yarascan_running = False
