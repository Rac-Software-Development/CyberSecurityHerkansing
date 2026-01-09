import sqlite3
from pathlib import Path

from lib.gpt.bloom_taxonomy import get_bloom_category


class PromptsModel:
    def __init__(self, database_file):
        self.database_file = Path(database_file)

    def get_cursor(self):
        conn = sqlite3.connect(self.database_file)
        cursor = conn.cursor()
        cursor.row_factory = sqlite3.Row
        return conn, cursor

    def get_all_prompts(self):
        conn, cursor = self.get_cursor()
        query = """
            SELECT * FROM prompts;
        """
        cursor.execute(query)
        return cursor.fetchall()

    def get_prompt(self, prompt_id):
        conn, cursor = self.get_cursor()
        query = """
            SELECT * FROM prompts WHERE prompts_id = ?;
        """
        cursor.execute(query, (prompt_id,))
        return cursor.fetchone()

    def get_taxonomy_suggestion(self, prompt_id, gpt_model, question, allowed_taxonomies):
        prompt = self.get_prompt(prompt_id)
        taxonomy_suggestion = get_bloom_category(question, prompt["prompt"], gpt_model)

        # Deze code kan slimmer en duidelijker. Wat ik nu doe is een fallback geven als er geen categorie
        # is gevonden.
        if not taxonomy_suggestion:
            print("AI suggestie niet leesbaar:")
            print(taxonomy_suggestion)
            return {
                "niveau": "",
                "uitleg": "Er is geen leesbare JSON code teruggekomen van de AI",
            }
        elif "niveau" not in taxonomy_suggestion:
            print("AI geen JSON:")
            print(taxonomy_suggestion)
            return {
                "niveau": "",
                "uitleg": "Het antwoord van de AI bevat foutieve JSON opmaak",
            }
        elif taxonomy_suggestion["niveau"] not in allowed_taxonomies:
            return {
                "niveau": "",
                "uitleg": "De door de AI opgegeven categorie is niet een valide taxonomie van Bloom",
            }
        else:
            # ... en als niets fout is gevonden geven we de gevonden categorie terug
            return taxonomy_suggestion

    def score_prompt(self, prompt_id, correct):
        # SQL is een volwaardige programmeertaal en heeft allemaal opties om direct in een query zaken op te tellen,
        # maar voor dit voorbeeld handelen we dit in Python af.
        prompt = self.get_prompt(prompt_id)
        new_questions_count = prompt["questions_count"] + 1
        new_questions_correct = prompt["questions_correct"]
        if correct:
            new_questions_correct += 1

        conn, cursor = self.get_cursor()
        query = """
            UPDATE prompts SET questions_count = ?, questions_correct = ? WHERE prompts_id = ?;
        """
        cursor.execute(query, (new_questions_count, new_questions_correct, prompt_id))
        conn.commit()
