from model.database import Database
from datetime import datetime
from flask import jsonify

def prompt_overview():
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()
    prompt_overview_query = "SELECT prompts.prompts_id, prompts.prompt, users.display_name as Redacteur, prompts.questions_count, prompts.questions_correct FROM prompts JOIN users ON users.user_id = prompts.user_id; "
    cursor.execute(prompt_overview_query)
    data = cursor.fetchall()
    return data


def insert_prompt():
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()
    #to get the date
    today_date = datetime.today().strftime('%Y-%m-%d')

    #query
    insert_prompt("INSERT INTO prompts (prompts_id, user_id, prompt, qeustion_count, questions_correct, date_created) VALUES (?,?,?,?,?,?) ")

    # cursor.execute(insert_prompt,(?,?,?,?,?,today_date))

def delete_prompt(prompts_id, delete_related_questions):
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()

    if delete_related_questions:
        cursor.execute("DELETE FROM questions WHERE prompts_id = ?;", (prompts_id,))

    cursor.execute("DELETE FROM prompts WHERE prompts_id = ?", (prompts_id,))
    conn.commit()

def get_prompt_info(prompts_id):
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()
    query = """
        SELECT 
            p.prompts_id, 
            p.prompt, 
            COUNT(q.questions_id) AS question_count
        FROM 
            prompts p
        LEFT JOIN 
            questions q 
        ON 
            p.prompts_id = q.prompts_id
        WHERE 
            p.prompts_id = ?
        GROUP BY 
            p.prompts_id"""
    result = cursor.execute(query, (prompts_id,)).fetchone()
    return result