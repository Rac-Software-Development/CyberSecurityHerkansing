import sqlite3
import os
import jwt

from datetime import datetime, timedelta
from functools import wraps

from flask import *

from lib.gpt.bloom_taxonomy import get_taxonomy
from model.database_model import insert_upload_to_database
from model.toetsvragen import Toetsvragen

from model.database_model import insert_upload_to_database
from model.index_page import display_question, get_proposal, update_taxonomy

from model.user import *
from model.export_vragen import *
from model.Prompt_overview import *

from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "development-secret-change-this")

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 3

def createToken(user_id, is_admin):
    payload = {
        "user_id": user_id,
        "is_admin": bool(is_admin),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, app.secret_key, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def decodetoken(token):
    try:
        data = jwt.decode(token, app.secret_key, algorithms=[JWT_ALGORITHM])
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_user_token():
    token = request.headers.get("Authorization")
    if not token:
        return None

    data = decodetoken(token)
    if not data:
        return None

    return data

@app.route('/')
def home_page():
   return render_template('home_page.html')


@app.route('/list_users', methods=['GET', 'POST'])
def list_user():
    if check_user_is_admin():
        page = int(request.args.get('page', 1))

        limit = 10
        start = (page - 1) * limit

        user_model = User()
        if request.method == 'POST':
            search = request.form['search']
            all_users = user_model.get_users_offset(start, limit, search)
            total_users = user_model.get_users(search)
        else:
            all_users = user_model.get_users_offset(start, limit)
            total_users = user_model.get_users()

        has_previous = start > 0
        has_next = start + limit < len(total_users)

        return render_template("user_list.html", all_users = all_users, page=page, has_previous=has_previous, has_next=has_next)
    else:
        return "Niet ingelogd of geen admin"


@app.route('/toetsvragenScherm')

@app.route('/toetsvragenScherm', methods=['GET'])
def toetsvragenScherm():
    if check_user_is_admin():
        page = int(request.args.get('page', 1))
        zoekwoord = request.args.get('zoekWoord', '')
        taxonomy_filter = request.args.get('taxonomy') == 'true'
        limit = 10
        start = (page - 1) * limit

        toetsvragen_model = Toetsvragen()

        if taxonomy_filter:
            query = 'SELECT * FROM questions WHERE taxonomy_bloom IS NOT NULL LIMIT ? OFFSET ?'
            all_questions = toetsvragen_model.cursor.execute(query, (limit, start)).fetchall()
            total_questions_query = 'SELECT COUNT(*) FROM questions WHERE taxonomy_bloom IS NOT NULL'
            total_questions = toetsvragen_model.cursor.execute(total_questions_query).fetchone()[0]
        else:
            all_questions = toetsvragen_model.getToetsvragen(start=start, limit=limit, search=zoekwoord)
            total_questions = toetsvragen_model.getTotalQuestions(search=zoekwoord)

        has_previous = start > 0
        has_next = start + limit < total_questions

        return render_template(
            "toetsvragenScherm.html",
            all_questions=all_questions,
            page=page,
            has_previous=has_previous,
            has_next=has_next,
            zoekwoord=zoekwoord,
            taxonomy_filter=taxonomy_filter
        )
    else:
        return "Niet ingelogd of geen admin"

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login_screen', methods=['GET', 'POST'])
def login_screen():
    if request.method == "POST":
        tries = session.get("login_tries", 0)
        if tries >= 5:
            flash("te veel mislukte pogingen probeer het later opnieuw", "error")
            return redirect(url_for("login_screen"))

        login = request.form['login']
        password = request.form["password"]

        print(login, password)

        if not login or not password:
            flash("please try again.", "error")
            return redirect(url_for('login_screen'))

        try:
            database = Database('./databases/database.db')
            cursor, conn = database.connect_db()

            cursor.execute('SELECT * FROM users WHERE login=?', (login,))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user["password"], password):
                session['user_id'] = user['user_id']
                session['username'] = user['login']
                session["admin"] = user["is_admin"] == 1
                session["login_tries"] = 0

                token = createToken(user["user_id"], user["is_admin"])
                flash('Logged in', 'success')
                resp = redirect(url_for('toetsvragenScherm'))
                resp.set_cookie(
                    "auth_token",
                    token,
                    httponly=True,
                    samesite="Lax"
                )
                return resp

                flash('logged in', 'success')
                return redirect(url_for('toetsvragenScherm'))
            else:
                session["login_tries"] = session.get("login_tries", 0) + 1
                flash('please try again', 'error')
                return redirect(url_for('login_screen'))

        except Exception as e:
            flash(f"An Error occurred: {e}", "danger")
            return redirect(url_for('login_screen'))

    return render_template("login_screen.html")

@app.route('/welcome')
def welcome():
    if not checkloggedin():
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login_screen'))

    return render_template("welcome.html", user=session['username'])

@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if check_user_is_admin():
        user_model = User()
        if request.method == 'POST':
            display_name = request.form['display_name']
            login = request.form['login']
            password = request.form['password']
            is_admin = request.form['is_admin']

            if not display_name or not login:
                flash("Dit veld mag niet leeg zij", "error")
                return redirect(url_for("add_user"))

            if password and len(password) < 6:
                flash("wachtwoord moet minimaal 6 tekens zijn", "error")
                return redirect(url_for("add_user"))

            if len(login) > 50 or len(display_name) > 100:
                flash("invoer is te lang", "error")
                return redirect(url_for("add_user"))

            update_user_status = user_model.update_user(user_id, login, password, display_name, is_admin)
            if update_user_status:
                return redirect(url_for('list_user'))
        else:
            user = user_model.get_user(user_id)
            return render_template("edit_user.html", user=user)
    else:
        return "Niet ingelogd of geen admin"


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if check_user_is_admin():
        user_model = User()
        if request.method == 'POST':
            display_name = request.form['display_name']
            login = request.form['login']
            password = request.form['password']
            is_admin = request.form['is_admin']

            create_user_status = user_model.create_user(login, password, display_name, is_admin)
            if create_user_status:
                return redirect(url_for('list_user'))
        else:
            return render_template("add_user.html")
    else:
        return "Niet ingelogd of geen admin"


@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    if check_user_is_admin():
        user_model = User()
        user_model.delete_user(user_id)
        return redirect(url_for('list_user'))
    else:
        return "Niet ingelogd of geen admin"


@app.route('/add_test_user')
def add_test_user():
    if check_user_is_admin():
        user_model = User()
        user_model.create_user("naam test1245", "pass", "display1345", "1")
        return redirect(url_for('list_user'))
    else:
        return "Niet ingelogd of geen admin"


# Import page & functions

@app.route('/import')
def import_page():
    return render_template('import_screen.html')


@app.route('/import', methods=['POST'])
def import_json():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    json_file = request.files['file']

    if json_file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    json_data = json.load(json_file)

    return insert_upload_to_database(json_data)

@app.route('/index/<question_id>')
def index_page(question_id):
    return display_question(question_id)

@app.route('/update_taxonomy', methods=['POST'])
def call_update_taxonomy():
    question_id = request.form.get('question_id')
    prompt  = request.form.get('prompt')
    prompt = clean_prompt(prompt)

    return update_taxonomy(question_id, prompt)

@app.route('/generate_proposal', methods=['POST'])
def generate_proposal():
    question_id = request.form.get('question_id')
    prompt = request.form.get('prompt')
    proposal = get_proposal(question_id, prompt)

    return display_question(question_id, proposal, prompt)

@app.route('/proposal_status', methods=['POST']) 
def proposal_status():
    question_id = request.form.get('question_id')
    if request.form.get('status') == 'approved':
        return update_taxonomy(question_id, request.form.get('proposal'))
    else:
        prompt = request.form.get('previous_prompt')
        proposal = get_proposal(question_id, prompt)
        return display_question(question_id, proposal)

def clean_prompt(prompt_with_error_margin):
    return prompt_with_error_margin.split(" - ", 1)[-1]

def check_user_is_admin():
    user_data = get_user_token()
    if user_data and user_data.get("is_admin"):
        return True

    if 'admin' not in session:
        return False
    if not session.get("admin"):
        return False

    return True

def checkloggedin():
    user_data = get_user_token()
    if user_data:
        return True
    return 'user_id' in session

@app.route('/export_vragen', methods=['POST','GET'])
def export_vragen():
    if not check_user_is_admin():
        return "niet ingelogd of niet ingelogd als admin"
    if request.method == 'POST':
        download_json = request.form['export_option'] == "1"
        has_tax = request.form.get('has_tax')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        use_date = request.form.get('between_date')
        mark_exported = request.form.get('exported')
        export_status_type = int(request.form.get('export_status_type'))
        limit = int(request.form.get('limit'))
        if use_date is None:
            start_date = end_date = None
        json_export = export_question_to_json(download_json, has_tax, start_date, end_date, mark_exported, export_status_type, limit)

        if json_export is None:
            return render_template('export_vragen.html', prompt="Deze combinatie geeft 0 vragen, probeer opnieuw")
        else:
            return json_export

    return render_template('export_vragen.html')

@app.route('/prompt_overview', methods=['GET', 'POST'])
def prompt_tabel():
    if not check_user_is_admin():
        return "niet ingelogd of niet ingelogd als admin"
    all_prompts = prompt_overview()

    return render_template("prompt_tabel.html", all_prompts=all_prompts)

@app.route('/prompt_input', methods=['GET', 'POST'])
def prompt_input():
    if not check_user_is_admin():
        return "niet ingelogd of niet ingelogd als admin"
    if request.method == 'POST':
        try:
            prompt_title = request.form['prompt_title'].strip()
            prompt = request.form['prompt'].strip()

            if not prompt_title or not prompt:
                flash("titel en prompt zijn verplicht!", "error")
                return redirect(url_for('prompt_input'))

            print(f"opgeslagen prompt: {prompt_title}")

            flash("prompt saved succesfully!", "success")
            return redirect(url_for('prompt_tabel'))
        except Exception as e:
            #unexpected error
            flash(f"Er is een error: {str(e)}", "error")
            return redirect(url_for('prompt_input'))

    return render_template('add_prompt.html')

@app.route('/prompt_verwijderen', methods=['GET', 'POST'])
def prompt_verwijderen():
    if not check_user_is_admin():
        return "niet ingelogd of niet ingelogd als admin"
    all_prompts = prompt_overview()

    return render_template("prompt_verwijderen.html", all_prompts=all_prompts)

@app.route('/delete_prompt/<prompt_id>', methods=['GET', 'POST'])
def delete_prompt_id(prompt_id):
    if not check_user_is_admin():
        return "niet ingelogd of niet ingelogd als admin"
    if check_user_is_admin():
        if request.method == 'POST':
            delete_option = request.form['delete_option']
            if delete_option == "0":
                delete_prompt(prompt_id, False)
            else:
                delete_prompt(prompt_id, True)
        else:
            row = get_prompt_info(prompt_id)
            if row:
                if row['question_count'] > 0:
                    print(f"prompt is gekoppeld aan {str(row['question_count'])} vragen")
                else:
                    print("prompt is niet gekoppeld aan een vraag")
                return render_template("prompt_verwijderen_opties.html", prompt=row)
            else:
                print("prompt ongeldig")
                return redirect(url_for('prompt_verwijderen'))

        return redirect(url_for('prompt_verwijderen'))
    else:
        return "Niet ingelogd of geen admin"

@app.route("/logout")
def logout():
    session.clear()
    resp = redirect(url_for("login_screen"))
    resp.delete_cookie("auth_token")
    return resp

if __name__ == "__main__":
    app.run(debug=True)

