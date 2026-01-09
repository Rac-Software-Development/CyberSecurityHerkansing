import json

from flask import jsonify

from model.database import Database

required_keys = [
    "question_id",
    "question",
    "answer",
    "vak",
    "onderwijsniveau",
    "leerjaar",
    "question_index"
]

def insert_upload_to_database(data):
        errors = []
        filtered_data = []

        for index, item in enumerate(data):
            missing_or_invalid = []

            # Check for missing or invalid required keys
            for key in required_keys:
                if key not in item or item[key] in [None, ""]:
                    missing_or_invalid.append(key)

            if missing_or_invalid:
                errors.append({
                    "question_id": item["question_id"] or index,
                    "error": 'Invalid keys in JSON item: ' + ', '.join(missing_or_invalid)
                })
                continue

            # Get all question id's from database
            questions = get_questions()
            duplicate = False

            if item['question_id'] in questions:
                errors.append({
                    "question_id": item['question_id'],
                    "error": 'Question already exists with ID ' + str(item['question_id'])
                })
                duplicate = True

            if not duplicate:
                filtered_data.append(item)

        if not errors:
            database = Database('./databases/database.db')
            cursor, conn = database.connect_db()

            insert_query = "INSERT INTO questions (questions_id, prompts_id, user_id, question, date_created) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)"

            # Insert each valid item into the database
            for item in filtered_data:
                questions_id = item.get("question_id")
                prompts_id = 0
                user_id = '1234'  # PLACEHOLDER EXAMPLE
                question = item.get("question")

                cursor.execute(insert_query, (
                    questions_id,
                    prompts_id,
                    user_id,
                    question
                ))

            conn.commit()
            conn.close()

            return jsonify({'error': False, 'message': 'Data successfully uploaded!'})
        else:
            # Return errors for invalid keys or duplicates
            return jsonify({
                'error': True,
                'message': 'JSON file error',
                'details': errors
            }), 400


def get_questions():
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()

    questions = cursor.execute("SELECT questions_id FROM questions")

    question_ids = []

    for question in questions:
        question_id = question[0]
        question_ids.append(question_id)

    conn.commit()
    conn.close()

    return question_ids

def get_question(question_id):
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()

    question = cursor.execute("SELECT * FROM questions WHERE questions_id = ?", (question_id,))
    question = question.fetchone()

    question = dict(question) if question else None

    conn.commit()
    conn.close()

    return question

def set_taxonomy(question_id, rtti, bloom):
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()

    if rtti:
        cursor.execute("UPDATE questions SET rtti = ? WHERE questions_id = ?", (rtti, question_id))

    if bloom:
        if bloom and isinstance(bloom, dict):
            bloom = json.dumps(bloom)

        cursor.execute("UPDATE questions SET taxonomy_bloom = ? WHERE questions_id = ?", (bloom, question_id))

    conn.commit()
    conn.close()

    return True

def get_prompts():
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()

    cursor = conn.cursor()

    cursor.execute("SELECT * FROM prompts")
    rows = cursor.fetchall()

    prompts = [dict(row) for row in rows] if rows else None

    conn.commit()
    conn.close()

    return prompts