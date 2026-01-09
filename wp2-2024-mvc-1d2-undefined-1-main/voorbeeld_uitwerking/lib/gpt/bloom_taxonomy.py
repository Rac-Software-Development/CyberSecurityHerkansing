import json
import traceback

from openai import OpenAI
from ollama import Client

gpt_model_map = {
    "dry_run": {
        "model": None,
        "endpoint": None,
        "api_key": None
    },
    "rac_test": {
        "model": "llama3.2",
        "endpoint": "https://ollama.rac-sd.nl",
        "api_key": None
    },
    "presentatie": {
        "model": "gpt-3.5-turbo",
        "endpoint": None,
        "api_key": "<jouw API key>"
    }
}


# Eem GPT reageert als Chatbot
def get_json_from_response(response):
    # Vaak geeft ChatGPT / Ollama een JSON terug, maar soms ook niet
    # We gaan dus op zoek naar de JSON in de response..
    start_bracket_index = response.find("{")
    if start_bracket_index == -1:
        raise ValueError("No JSON found in response")
    # ..rfind zoekt achterin de string naar het laatste voorkomen van een karakter
    end_bracket_index = response.rfind("}")
    if end_bracket_index == -1:
        raise ValueError("No JSON found in response")

    # We nemen de substring vanaf de start tot en met het einde van de JSON
    json_string = response[start_bracket_index:end_bracket_index + 1]

    # We laden de JSON string in een Python dictionary
    try:
        result = json.loads(json_string)
    except json.JSONDecodeError as e:
        print(json_string)
        raise e
    return result


def get_openai_chat(question, prompt, settings):
    client = OpenAI(api_key=settings.get("api_key"))
    completion = client.chat.completions.create(
        model=settings["model"],  # alternatieven zijn gpt-3.5-turbo en gpt-4.0-turbo
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": question}
        ]
    )
    if len(completion.choices) == 0:
        raise ValueError("No completion found")

    raw_content = completion.choices[0].message.content
    result = get_json_from_response(raw_content)
    return result


def get_ollama_chat(question, prompt, settings):
    client = Client(host=settings.get("endpoint"))
    messages = [
        {
            'role': 'system',
            'content': prompt,
        },
        {
            'role': 'user',
            'content': question,
        },
    ]
    response = client.chat(model=settings.get("model"), messages=messages)
    if 'message' not in response or 'content' not in response['message']:
        print(response)
        raise ValueError("No message in response")

    raw_content = response['message']['content']
    result = get_json_from_response(raw_content)
    return result


def get_bloom_category(question, prompt, gpt):
    result = None
    if gpt not in gpt_model_map:
        raise ValueError(f"GPT {gpt} is niet bekend in de gpt_model_map")

    settings = gpt_model_map[gpt]

    try:
        match gpt:
            case "dry_run":
                print("No model given, we are returning a static answer for testing")
                result = {
                    "categorie": "Onthouden",
                    "uitleg": "De vraag vereist het onthouden van feitelijke informatie over de Grutto, zoals zijn classificatie als vogelsoort."
                }
            case "rac_test":
                result = get_ollama_chat(question, prompt, settings)
            case "presentatie":
                result = get_openai_chat(question, prompt, settings)
    except Exception as e:
        traceback.print_exc()
        print(e)
    finally:
        return result


if __name__ == "__main__":
    prompt = """ 
    Gebruik de taxonomie van Bloom om de volgende vraag in één van de niveaus "Onthouden", "Begrijpen", "Toepassen", "Analyseren", "Evalueren" en "Creëren" en leg uit waarom je dat niveau hebt gekozen. Geef het antwoord in een RFC8259 JSON met de volgende opmaak:
    {
       "niveau": "niveau van Bloom",
       "uitleg": "uitleg waarom dit niveau van toepassing is"
    }
    """
    question = "Wat is de hoofdstad van Nederland?"

    # De keuze is dus tussen "dry_run", "rac_test" en "presentatie"
    # Het antwoord komt terug als een dictionary:
    # {
    #    "niveau": "niveau van Bloom",
    #    "uitleg": "uitleg waarom dit niveau van toepassing is"
    # }
    print(get_bloom_category(question, prompt, "rac_test"))
