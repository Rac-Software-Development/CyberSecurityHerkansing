from model.database import Database
from werkzeug.security import generate_password_hash

class User():
    def __init__(self):
        database = Database('./databases/database.db')
        self.cursor, self.con = database.connect_db()

    def get_users(self, search = None):
        if search:
            result = self.cursor.execute('SELECT * FROM users WHERE display_name LIKE ?', (f"%{search}%",)).fetchall()
        else:
            result = self.cursor.execute('SELECT * FROM users').fetchall()
        return result

    def get_users_offset(self, start, limit, search = None):
        if search:
            result = self.cursor.execute('SELECT * FROM users WHERE display_name LIKE ? LIMIT ? OFFSET ?', (f"%{search}%", limit, start)).fetchall()
        else:
            result = self.cursor.execute('SELECT * FROM users LIMIT ? OFFSET ?', (limit, start)).fetchall()
        return result

    def login_user(self, login, password):
        login_query = 'SELECT 1 FROM users WHERE login = ?LIMIT 1'
        ##hash passwords????
        result = self.cursor.execute(login_query, (login,)).fetchone()
        if result:
            stored_password = result[0]
            if password == stored_password:
                return True

        return False #login fail


    def get_user(self, user_id):
        result = self.cursor.execute("SELECT * FROM users WHERE user_id = ?", (str(user_id),)).fetchone()
        return result

    def create_user(self, login, password, display_name, is_admin):
        hashed_password = generate_password_hash(password)
        self.cursor.execute(
            "INSERT into users (login, password, display_name, is_admin) VALUES (?, ?, ?, ?)",
            (login, password, display_name, is_admin))
        self.con.commit()

        return True

    def update_user(self, user_id, login, password, display_name, is_admin):
        hashed_password = generate_password_hash(password)
        self.cursor.execute(
            'UPDATE users SET login = ?, password = ?, display_name = ?, is_admin = ? WHERE user_id = ?',
            (login, password, display_name, is_admin, user_id)
        )
        self.con.commit()

        return True

    def delete_user(self, user_id):
        print(user_id)
        self.cursor.execute("DELETE FROM users WHERE user_id = ?", (str(user_id),))
        self.con.commit()