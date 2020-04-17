"""
<filename>.py

Author: Desmond Tan
"""

import sqlite3

conn = sqlite3.connect('file_metadata.sqlite3')
c = conn.cursor()

c.execute('''CREATE TABLE FILES_METADATA
             (
                [file_id] INTEGER PRIMARY KEY, 
                [hostname] text, 
                [filename] text, 
                [root] text,
                [hashed] text, 
                [file_type] text, 
                [file_size] integer
             )
          ''')

c.execute('''CREATE TABLE VTOTAL_RESULTS
             (
                [result_id] INTEGER PRIMARY KEY, 
                [hashed] text, 
                [vtotal_results] text
             )
          ''')

c.execute('''CREATE TABLE YARA_RESULTS
             (
                [result_id] INTEGER PRIMARY KEY, 
                [hashed] text, 
                [yara_results] text
             )
          ''')

conn.commit()
