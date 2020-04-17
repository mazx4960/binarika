"""
<filename>.py

Author: Desmond Tan
"""

#################
# Imports
#################

from flask_restful import Resource, reqparse
from helper_functions import get_db


#################
# Classes
#################

class APIHandler(Resource):
    def get(self):
        pass

    def post(self):
        db = get_db()

        parser = reqparse.RequestParser()
        parser.add_argument('hostname', required=True)
        parser.add_argument('filename', required=True)
        parser.add_argument('root', required=True)
        parser.add_argument('hashed', required=True)
        parser.add_argument('file_type', required=True)
        parser.add_argument('file_size', required=True)
        args = parser.parse_args()

        # check file exists
        file_data = db.execute('SELECT * FROM FILES_METADATA WHERE hostname=? AND filename=? AND root=?',
                               (args['hostname'], args['filename'], args['root'])).fetchall()
        if file_data != []:
            return 'File already exist in database', 400

        db.execute('INSERT INTO FILES_METADATA (hostname, filename, root, hashed, file_type, file_size) '
                   'VALUES(?, ?, ?, ?, ?, ?)',
                   (args['hostname'], args['filename'], args['root'], args['hashed'], args['file_type'],
                    args['file_size'])
                   )
        db.commit()
        return 201

    def put(self):
        pass

    def delete(self):
        pass
