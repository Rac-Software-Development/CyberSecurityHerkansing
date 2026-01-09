import sqlite3
from pathlib import Path


class QuestionsModel:
    def __init__(self, database_file):
        self.database_file = Path(database_file)

    def get_allowed_taxonomies(self):
        return ["Onthouden", "Begrijpen", "Toepassen", "Analyseren", "Evalueren", "Creëren"]

    def get_cursor(self):
        conn = sqlite3.connect(self.database_file)
        cursor = conn.cursor()
        cursor.row_factory = sqlite3.Row
        return conn, cursor

    def get_all_questions(self):
        conn, cursor = self.get_cursor()
        query = """
            SELECT * FROM questions;
        """
        cursor.execute(query)
        return cursor.fetchall()

    def get_question(self, question_id):
        conn, cursor = self.get_cursor()
        query = """
            SELECT * FROM questions WHERE questions_id = ?;
        """
        cursor.execute(query, (question_id,))
        return cursor.fetchone()

    def save_question_categorization(self, question_id, taxonomy):
        conn, cursor = self.get_cursor()
        query = """
            UPDATE questions SET taxonomy_bloom = ? WHERE questions_id = ?;
        """
        cursor.execute(query, (taxonomy, question_id))
        conn.commit()
