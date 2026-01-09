import sqlite3 # Imports the sqlite3 module

class Database(object):
    def __init__(self, path):
        self.path = path # Ask for the database file path whenever Database() is called

    def connect_db(self):
        con = sqlite3.connect(self.path) # Make a connection with the database stored in path
        con.row_factory = sqlite3.Row # Save results in rows instead of a tuple
        cursor = con.cursor() # Cursor for executing SQL statements
        return cursor, con # Return the cursor and the db connection