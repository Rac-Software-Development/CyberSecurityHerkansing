from model.database import Database
from flask import jsonify

def export_question_to_json(save, has_tax, start_date, end_date, mark_exported, export_status_type, limit):
    database = Database('./databases/database.db')
    cursor, conn = database.connect_db()

    select_query = "SELECT questions_id, prompts_id, user_id, question, taxonomy_bloom, rtti, exported, date_created FROM questions"
    if has_tax and start_date and end_date:
        select_query += " WHERE (taxonomy_bloom IS NOT NULL OR rtti IS NOT NULL) AND (date_created BETWEEN '"+start_date+"' AND '"+end_date+"')"
    elif start_date and end_date:
        select_query += " WHERE date_created BETWEEN '"+start_date+"' AND '"+end_date+"'"
    elif has_tax:
        select_query += " WHERE (taxonomy_bloom IS NOT NULL OR rtti IS NOT NULL)"

    if export_status_type is not 0:
        if "WHERE" in select_query:
            select_query += " AND"
        else:
            select_query += " WHERE"
        if export_status_type == 1:
            select_query += " exported == 0"
        if export_status_type == 2:
             select_query += " exported > 0"

    if limit > 0:
        select_query += " LIMIT "+str(limit)

    cursor.execute(select_query)
    print(select_query)
    rows = cursor.fetchall()

    if len(rows) == 0:
        return None

    if mark_exported:
        for row in rows:
            cursor.execute(
                'UPDATE questions SET exported = exported + 1 WHERE questions_id = ?', (row['questions_id'],)
            )
            conn.commit()

    return create_json(rows, save)

def create_json(rows, save = False):
    data = []
    for row in rows:
        dictionary = {}
        dictionary['questions_id'] = row['questions_id']
        dictionary['prompts_id'] = row['prompts_id']
        dictionary['question'] = row['question']
        dictionary['taxonomy_bloom'] = row['taxonomy_bloom']
        dictionary['rtti'] = row['rtti']
        dictionary['exported'] = row['exported']
        dictionary['date_created'] = row['date_created']
        data.append(dictionary)

    response = jsonify(data)

    if save:
        response.headers["Content-Disposition"] = "attachment; filename=questions.json"
        response.headers["Content-Type"] = "application/json"

    return response