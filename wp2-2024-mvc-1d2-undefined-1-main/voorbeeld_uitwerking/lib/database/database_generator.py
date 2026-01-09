import sqlite3
from pathlib import Path


class WP2DatabaseGenerator:
    def __init__(self, database_file, overwrite=False, initial_data=False):
        self.database_file = Path(database_file)
        self.create_initial_data = initial_data
        self.database_overwrite = overwrite
        self.test_file_location()
        self.conn = sqlite3.connect(self.database_file)

    def generate_database(self):
        self.create_table_questions()
        self.create_table_users()
        self.create_table_prompts()
        if self.create_initial_data:
            self.insert_admin_user()
            self.create_example_prompts()
            self.create_example_questions()


    def create_table_users(self):
        create_statement = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT NOT NULL,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_admin INTEGER NOT NULL DEFAULT 1);
        """
        self.__execute_transaction_statement(create_statement)
        print("✅ Users table created")

    def create_table_prompts(self):
        # Ik heb hier een "name" kolom toegevoegd, omdat ik het handig vind om een naam te geven aan een prompt
        create_statement = """
        CREATE TABLE IF NOT EXISTS prompts (
            prompts_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,            
            label TEXT NOT NULL,            
            prompt TEXT NOT NULL,
            questions_count INTEGER NOT NULL,
            questions_correct INTEGER NOT NULL,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)            
            );
        """
        self.__execute_transaction_statement(create_statement)
        print("✅ Prompts table created")
    def create_table_questions(self):
        create_statement = """
        CREATE TABLE IF NOT EXISTS questions (
            questions_id TEXT PRIMARY KEY NOT NULL,
            prompts_id INTEGER,
            user_id TEXT INTEGER NULL,
            question TEXT NOT NULL,
            taxonomy_bloom TEXT,
            rtti TEXT,
            exported BOOLEAN DEFAULT FALSE,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (prompts_id) REFERENCES prompts(prompts_id)            
            );
        """
        self.__execute_transaction_statement(create_statement)
        print("✅ Questions table created")



    def insert_admin_user(self):
        users = [
            ( "krugw@hr.nl", "geheim", "Gerard van Kruining", 1),
            ( "vried@hr.nl", "geheimer", "Diederik de Vries", 0),
        ]
        insert_statement = "INSERT INTO users (login, password, display_name, is_admin) VALUES (?, ?, ?, ?);"
        self.__execute_many_transaction_statement(insert_statement, users)
        print("✅ Default teachers / users created")

    # Transacties zijn duur, dat wil zeggen, ze kosten veel tijd en CPU kracht. Als je veel insert doet
    # bundel je ze in één transactie, of je gebruikt de SQLite executemany methode.
    def __execute_many_transaction_statement(
        self, create_statement, list_of_parameters=()
    ):
        c = self.conn.cursor()
        c.executemany(create_statement, list_of_parameters)
        self.conn.commit()

    def __execute_transaction_statement(self, create_statement, parameters=()):
        c = self.conn.cursor()
        c.execute(create_statement, parameters)
        self.conn.commit()

    def test_file_location(self):
        if not self.database_file.parent.exists():
            raise ValueError(
                f"Database file location {self.database_file.parent} does not exist"
            )
        if self.database_file.exists():
            if not self.database_overwrite:
                raise ValueError(
                    f"Database file {self.database_file} already exists, set overwrite=True to overwrite"
                )
            else:
                # Unlink verwijdert een bestand
                self.database_file.unlink()
                print("✅ Database already exists, deleted")
        if not self.database_file.exists():
            try:
                self.database_file.touch()
                print("✅ New database setup")
            except Exception as e:
                raise ValueError(
                    f"Could not create database file {self.database_file} due to error {e}"
                )

    def create_example_prompts(self):
        prompts = [
            {
                "name": "Alex prompt v1",
                "prompt": """
                Gebruik de taxonomie van Bloom om de volgende vraag in één van de niveaus 
                "Onthouden", "Begrijpen", "Toepassen", "Analyseren", "Evalueren" en "Creëren"
                 en leg uit waarom je dat niveau hebt gekozen. Geef het antwoord in een RFC8259 
                 JSON met de volgende opmaak:
                {
                   "niveau": "niveau van Bloom",
                   "uitleg": "uitleg waarom dit niveau van toepassing is"
                }            
                """
            },
            {
                "name": "Alex prompt v2",
                "prompt": """
                   Scoor deze toetsvraag op de taxonomie van bloom en geef antwoord in een RFC8259 JSON met opmaak:
                    {
                        "niveau": "Onthouden", "Begrijpen", "Toepassen", "Analyseren", "Evalueren" of "Creëren",
                        "uitleg": "uitleg waarom dit niveau van toepassing is"
                    }
                """
            }
        ]
        for prompt in prompts:
            insert_statement = "INSERT INTO prompts (user_id, label, prompt, questions_count, questions_correct) VALUES (?, ?, ?, ?, ?);"
            self.__execute_transaction_statement(insert_statement, (1, prompt["name"], prompt["prompt"], 0, 0))
        print("✅ Example prompts created")

    def create_example_questions(self):
        questions = [
            {
                "question_id": "DDE8A96F7AD24E87B44317F05107274C",
                "question": "Wat is de hoofdstad van Nederland?",
            },
            {
                "question_id": "DDE8A96F7AD24E87B44311234107274C",
                "question": "Een familie oogst 200 kg zeewier per week. 30% wordt verkocht aan een fabriek die er medicijnen van maakt en 55 % wordt verkocht aan een winkel. Hoeveel kg houdt de familie per week over? Kun je een schatting maken van hoeveel bladgroen er in deze hoeveelheid zit? Hoe zou je dat kunnen doen?",
            },
            {
                "question_id": "1234A96F7AD24E87B44311234107274C",
                "question": "Kun je een definitie opstellen waarin je uitlegt wat een hoofdstad is?",
            },
        ]
        for question in questions:
            insert_statement = "INSERT INTO questions (questions_id, question) VALUES (?, ?);"
            self.__execute_transaction_statement(insert_statement, (question["question_id"], question["question"],))
        print("✅ Example questions created")


if __name__ == "__main__":
    my_path = Path(__file__).parent.resolve()
    project_root = my_path.parent.parent
    # Deze slashes komen uit de "Path" module. Dit is een module die je kan gebruiken
    # om paden te maken. Dit is handig omdat je dan niet zelf hoeft te kijken of je
    # een / (mac) of een \ (windows) moet gebruiken.
    database_path = project_root / "databases" / "database.db"
    database_generator = WP2DatabaseGenerator(
        database_path, overwrite=True, initial_data=True
    )
    database_generator.generate_database()
