def download_tika_data():
    import requests

    resp = requests.get(
        "https://raw.githubusercontent.com/apache/tika/main/tika-core/src/main/resources/org/apache/tika/mime/tika-mimetypes.xml"
    )
    print(resp.text)
