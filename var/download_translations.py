import requests
import shutil
import os

POEDITOR_API_KEY = os.environ['POEDITOR_API_KEY']
POEDITOR_PROJECT_ID = os.environ['POEDITOR_PROJECT_ID']


LANGUAGE_CODES = [
    "af", "sq", "ar-sa", "ar-iq", "ar-eg", "ar-ly", "ar-dz", "ar-ma", "ar-tn", "ar-om",
    "ar-ye", "ar-sy", "ar-jo", "ar-lb", "ar-kw", "ar-ae", "ar-bh", "ar-qa", "eu", "bg",
    "be", "ca", "zh-tw", "zh-cn", "zh-hk", "zh-sg", "hr", "cs", "da", "nl", "nl-be", "en",
    "en-us", "en-eg", "en-au", "en-gb", "en-ca", "en-nz", "en-ie", "en-za", "en-jm",
    "en-bz", "en-tt", "et", "fo", "fa", "fi", "fr", "fr-be", "fr-ca", "fr-ch", "fr-lu",
    "gd", "gd-ie", "de", "de-ch", "de-at", "de-lu", "de-li", "el", "he", "hi", "hu",
    "is", "id", "it", "it-ch", "ja", "ko", "lv", "lt", "mk", "mt", "no", "pl",
    "pt-br", "pt", "rm", "ro", "ro-mo", "ru", "ru-mi", "sz", "sr", "sk", "sl", "sb",
    "es", "es-ar", "es-gt", "es-cr", "es-pa", "es-do", "es-mx", "es-ve", "es-co",
    "es-pe", "es-ec", "es-cl", "es-uy", "es-py", "es-bo", "es-sv", "es-hn", "es-ni",
    "es-pr", "sx", "sv", "sv-fi", "th", "ts", "tn", "tr", "uk", "ur", "ve", "vi", "xh",
    "ji", "zu", "ar", "bn", "zh-hant"
]

FOLDER_MAPPING = {
    "zh-cn": ["zh-cn", "zh"],
}



def download_language(lang):
    data = [
        ('api_token', POEDITOR_API_KEY),
        ('action', 'export'),
        ('id', POEDITOR_PROJECT_ID),
        ('language', lang),
        ('type', 'mo'),
    ]

    r = requests.post('https://poeditor.com/api/', data=data, timeout=20.0)

    if not r.ok:
        print("Error: download_language")
        print(r.text)
        exit(1)

    result = r.json()

    r = requests.get(result['item'], stream=True, timeout=20.0)

    if r.status_code == 200:
        folder_paths = [os.path.join('psono', 'locale', lang, 'LC_MESSAGES')]
        if lang in FOLDER_MAPPING:
            folder_paths = []
            for folder in FOLDER_MAPPING[lang]:
                folder_paths.append(os.path.join('psono', 'locale', folder, 'LC_MESSAGES'))
        for folder_path in folder_paths:
            os.makedirs(folder_path, exist_ok=True)
            path = os.path.join(folder_path, 'django.mo')
            with open(path, 'wb') as f:
                r.raw.decode_content = True
                shutil.copyfileobj(r.raw, f)

    print("Success: download_language " + lang)

    return path


def get_languages():
    data = [
      ('api_token', POEDITOR_API_KEY),
      ('id', POEDITOR_PROJECT_ID),
    ]

    r = requests.post('https://api.poeditor.com/v2/languages/list', data=data, timeout=20.0)
    if not r.ok:
        print("Error: get_languages")
        print(r.json())
        exit(1)
    result = r.json()
    print(result['result']['languages'])
    return result['result']['languages']



def main():

    # Download
    languages = get_languages()
    for lang in languages:
        language_code = lang['code'].lower()
        if language_code not in LANGUAGE_CODES:
            print("Error: main")
            print("Invalid Language Code " + language_code)
            exit(1)
        file = download_language(language_code)

    print("Success")

if __name__ == "__main__":
    main()
