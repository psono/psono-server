import requests
import os
import json

POEDITOR_API_KEY = os.environ['POEDITOR_API_KEY']
POEDITOR_PROJECT_ID = os.environ['POEDITOR_PROJECT_ID']


FILE_PATHS = {
    'en': 'locale/en/LC_MESSAGES/django.po',
}

def upload_language(lang):

    if lang in FILE_PATHS:
        data = {
            'id': POEDITOR_PROJECT_ID,
            'api_token': POEDITOR_API_KEY,
            'updating': 'terms',
            'language': lang,
            'sync_terms ': 1,
        }
        with open(FILE_PATHS[lang], 'rb') as file:
            r = requests.post('https://api.poeditor.com/v2/projects/upload', data=data, files={'file': file}, timeout=20.0)

        if not r.ok:
            print("Error: upload_language " + lang)
            print(r.text)
            exit(1)
        content = json.loads(r.content)
        if "response" not in content or "status" not in content["response"] or content["response"]["status"] != 'success':
            print("Error: upload_language " + lang)
            print(r.text)
            exit(1)

    else:
        print("Error: upload_language " + lang + " No FILE_PATHS configured for this language")
        exit(1)

    print("Success: upload_language " + lang)

def main():
    # Upload
    for lang in FILE_PATHS:
        upload_language(lang)

    print("Success")

if __name__ == "__main__":
    main()
