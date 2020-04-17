"""
<filename>.py

Author: Desmond Tan
"""

#################
# Imports
#################

from api import *
from helper_functions import *


#################
# Constants and Global variables
#################

WORKER_LIMIT = 3
YARA_RULES_FOLDER = 'yara_rules'


#################
# Initialisation
#################

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = './uploads'
app.secret_key = b'supposed_to_be_a_secret!'

api = Api(app)
api.add_resource(APIHandler, '/api')

init_db()


#################
# Views
#################

@app.route('/')
def index():
    """
    Home page of the binarika server
    :return:
    """

    db = get_db()

    files_data_raw = db.execute('SELECT * FROM FILES_METADATA').fetchall()

    files_data = []
    for file_data in files_data_raw:
        files_data.append(extract_file_data(file_data))

    return render_template('index.html', files_data=files_data)


@app.route('/search_results', methods=['POST'])
def search_results():
    """
    Search results for keywords
    :return:
    """

    search_text = request.form.get('search_text')

    db = get_db()
    files_data_raw = db.execute('SELECT * FROM FILES_METADATA').fetchall()

    files_data = []
    for file_data in files_data_raw:
        search_fields = ['filename', 'root', 'hashed', 'hostname']
        for field in search_fields:
            if search_text.lower() in file_data[field].lower():
                files_data.append(extract_file_data(file_data))
                break

    return render_template('index.html', files_data=files_data)


@app.route('/yara_rules')
def yara_rules():
    rules = os.listdir(YARA_RULES_FOLDER)
    return render_template('yara_rules.html', rules=rules)


@app.route('/view_rule/<rule>')
def view_rule(rule):
    rule_path = os.path.join(YARA_RULES_FOLDER, rule)
    with open(rule_path, 'r') as rule_file:
        contents = rule_file.read().split('\n')
    return render_template('view_rule.html', contents=contents, rule=rule)


@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
    return Response(status=200)


@app.route('/view_file/<int:file_id>')
def view_file(file_id):
    """
    View page for individual files
    :param file_id: the id of the file
    :return:
    """

    db = get_db()
    file_data = db.execute('SELECT * FROM FILES_METADATA WHERE file_id=?', (file_id,)).fetchall()[0]
    vt_results = db.execute('SELECT * FROM VTOTAL_RESULTS WHERE hashed=?', (file_data['hashed'],)).fetchall()
    yara_results = db.execute('SELECT * FROM YARA_RESULTS WHERE hashed=?', (file_data['hashed'],)).fetchall()
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])

    file_data = dict(file_data)
    file_data['Uploaded'] = 'Yes' if file_data['hashed'] in uploaded_files else 'No'
    file_data['vt_results'] = json.loads(vt_results[0]['vtotal_results']) if vt_results != [] else {}
    file_data['yara_results'] = json.loads(yara_results[0]['yara_results']) if yara_results != [] else []

    return render_template('view_file.html', file_data=file_data)


@app.route('/filescan/<int:file_id>/<hashed>')
def scan_file(file_id, hashed):
    """
    Manual scan of files
    :param file_id: the id of the file
    :param hashed: the hashed value of the file
    :return:
    """

    params = {
        'apikey': VIRUS_TOTAL_APIKEY,
        'resource': hashed
    }
    response = requests.get(VIRUS_TOTAL_API, params=params)

    if response.status_code == 200:
        vt_results = json.dumps(response.json())

        db = get_db()
        db.execute('INSERT INTO VTOTAL_RESULTS (hashed, vtotal_results) VALUES(?, ?)', (hashed, vt_results))
        db.commit()

    return redirect(url_for('view_file', file_id=file_id))


@app.route('/yarascan/<int:file_id>/<hashed>')
def scan_yara(file_id, hashed):
    """
    Manual scan of files
    :param file_id: the id of the file
    :param hashed: the hashed value of the file
    :return:
    """
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], hashed)
    if not os.path.isfile(filepath):
        flash('File {} could not be found'.format(hashed))
        return redirect(url_for('view_file', file_id=file_id))

    rules = compile_yara_rules()
    with open(filepath, 'r') as bin_file:
        matches = rules.match(data=bin_file.read())

    matched_rules = extract_rules(matches)

    db = get_db()
    yara_results = db.execute('SELECT * FROM YARA_RESULTS WHERE hashed=?', (hashed,)).fetchall()

    if yara_results != []:
        db.execute('UPDATE YARA_RESULTS SET yara_results=? WHERE hashed=?', (json.dumps(matched_rules), hashed))
    else:
        db.execute('INSERT INTO YARA_RESULTS (hashed, yara_results) VALUES(?, ?)', (hashed, json.dumps(matched_rules)))
    db.commit()

    return redirect(url_for('view_file', file_id=file_id))


@app.route('/filescan/')
def background_filescan():
    """
    A page to initialise filescan
    :return:
    """
    global filescan_running

    db = get_db()
    file_hashes = db.execute('SELECT hashed FROM FILES_METADATA').fetchall()
    file_hashes = set(file_hashes)

    vt_hashes = db.execute('SELECT hashed FROM VTOTAL_RESULTS').fetchall()
    vt_hashes = set(vt_hashes)

    pending_hashes = file_hashes - vt_hashes

    if not filescan_running:
        filescan_running = True
        print 'background file scan'
        thread = Thread(target=filescan_handler, args=(pending_hashes,))
        thread.daemon = True
        thread.start()
    else:
        flash('File scan already running!')
        print 'file scan already running'

    return redirect(url_for('index'))


@app.route('/yarascan/')
def background_yarascan():
    """
    A page to initialise filescan
    :return:
    """
    global yarascan_running

    pending_hashes = os.listdir(app.config['UPLOAD_FOLDER'])
    pending_hashes = set(pending_hashes)

    if not yarascan_running:
        yarascan_running = True
        print 'background yara scan'
        thread = Thread(target=yara_scan, args=(pending_hashes, app.config['UPLOAD_FOLDER']))
        thread.daemon = True
        thread.start()
    else:
        flash('Yara scan already running!')

    return redirect(url_for('index'))
