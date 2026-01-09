from flask import Flask, render_template, request, redirect, url_for

from voorbeeld_uitwerking.lib.prompts_model import PromptsModel
from voorbeeld_uitwerking.lib.questions_model import QuestionsModel

# This is a small flask app to demonstrate the dialog needed to categorize a question using Bloom's taxonomy

app = Flask(__name__)
app.config["DB_FILE"] = "databases/database.db"
app.config["GPT_MODEL"] = "rac_test"


@app.route("/")
def list_questions():
    message = request.args.get("message")
    # Stap 1: Toon een lijst met vragen waar een redacteur een vraag uit kan kiezen om te categoriseren
    all_questions = questions_model.get_all_questions()
    return render_template(
        "questions.html.jinja", questions=all_questions, message=message
    )


@app.route("/question/<question_id>")
def show_question(question_id):
    # Stap 2: Toon de vraag en een lijst met bekende prompts waaruit de redacteur kan kiezen
    question = questions_model.get_question(question_id)
    all_prompts = prompts_model.get_all_prompts()
    return render_template(
        "question.html.jinja", question=question, prompts=all_prompts
    )


@app.route("/question/<question_id>/prompt", methods=["POST"])
def show_question_with_taxonomy_proposal(question_id):
    # Stap 3: Nadat een prompt is gekozen kunnen we een voorstel voor de taxonomie tonen
    # Daarvoor hebben we het ID nodig van de gekozen prompt. Die kregen we mee in de POST request
    prompt_id = request.form.get("prompt_id")
    if not prompt_id:
        return "Please select a prompt", 400

    # Om een prompt te tonen hebben we de vraag weer nodig, die halen weer eerst weer op
    # Let op: question is een dictionary met de vraag en de ID van de vraag
    question = questions_model.get_question(question_id)

    # We hebben ook een lijst met toegestane taxonomieën nodig, zodat we kunnen controleren
    # of de AI een valide taxonomie heeft voorgesteld
    allowed_taxonomies = questions_model.get_allowed_taxonomies()

    # Tijd om de AI te voeren. Als je onze functie gebruikt uit "bloom_taxonomy.py" krijg je
    # een dictionary terug, maar daar kan nog troep in zitten. Dat wil ik niet in mijn controller
    # code hebben, dat is de verantwoordelijkheid van het model.
    # Kijk dus even naar die code om te zien hoe dat werkt.
    taxonomy_suggestion = prompts_model.get_taxonomy_suggestion(
        prompt_id, app.config["GPT_MODEL"], question["question"], allowed_taxonomies
    )

    # Ik heb voor het opslaan later ook de prompt_id nodig. Ik ga die dus doorgeven aan mijn jinja
    # template en vanaf daar weer door naar de volgende functie waarin ik de prompts scoor.
    return render_template(
        "question_with_taxonomy.html.jinja",
        question=question,
        taxonomy_suggestion=taxonomy_suggestion,
        allowed_taxonomies=allowed_taxonomies,
        prompt_id=prompt_id,
    )


@app.route("/question/<question_id>/prompt/<int:prompt_id>/save", methods=["POST"])
def save_taxonomy(question_id, prompt_id):
    # Stap 4: We gaan nu twee dingen opslaan:
    # - de keuze van de redacteur en de taxonomie die de GPT heeft voorgesteld
    # - het aantal correcte categorisaties van de vraag

    # In het formulier op de vorige pagina hebben we twee velden:
    # - taxonomy: de keuze van de redacteur
    # - gpt_taxonomy: de taxonomie die de GPT heeft voorgesteld
    editor_taxonomy = request.form.get("taxonomy")
    gpt_taxonomy = request.form.get("gpt_taxonomy")
    ai_guessed_correct = editor_taxonomy == gpt_taxonomy
    prompts_model.score_prompt(prompt_id, ai_guessed_correct)

    # #n daarna gaan we het gekozen niveau in de vraag opslaan
    questions_model.save_question_categorization(question_id, editor_taxonomy)

    # We gaan terug naar de lijst met vragen. We kunnen de gebruiker ook een bedankje tonen.
    # We hebben in stap 1 al een functie geschreven die de lijst met vragen toont, dus die kunnen we hier weer gebruiken
    return redirect(
        url_for(
            "list_questions",
            message=f"De vraag is bijgewerkt met een niveau ({editor_taxonomy})!",
        )
    )


if __name__ == "__main__":
    prompts_model = PromptsModel(app.config["DB_FILE"])
    questions_model = QuestionsModel(app.config["DB_FILE"])
    app.run(debug=True)
