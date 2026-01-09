import json

from flask import *

from lib.gpt.bloom_taxonomy import gpt_model_map, get_taxonomy
from model.database_model import *


def display_question(question_id, proposal=None, previous_prompt=None):
    question =  get_question(question_id)
    if question["taxonomy_bloom"]:
        question["taxonomy_bloom"] = json.loads(question["taxonomy_bloom"])

    prompts = get_prompts()

    for prompt in prompts:
        prompt["error_margin"] = int((prompt["questions_correct"] / prompt["questions_count"]) * 100)

    return render_template('index_page.html', question=question, models=gpt_model_map, prompts=prompts, proposal=proposal, previous_prompt=previous_prompt)

def update_taxonomy(question_id, prompt):
    question = get_question(question_id)


    taxonomy = get_taxonomy(question["question"], prompt, "rac_test")

    set_taxonomy(question_id, False, taxonomy)

    return redirect(url_for('index_page', question_id=question_id))

def get_proposal(question_id, prompt):
    question = get_question(question_id)
    #proposal = get_taxonomy(question["question"], prompt, "rac_test")

    proposal = {
            "niveau": "Analyseren",
            "uitleg": "De vraag vereist dat de informatie wordt geëvalueerd en ingedeeld in de juiste categorie binnen Bloom’s taxonomie. Dit betekent dat de vraag verder gaat dan alleen onthouden of begrijpen; het vereist het ontleden van de vraag om te bepalen welk cognitief niveau het beste past."
            }   # FAllback for testing

    return proposal

