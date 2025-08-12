class SDKConfig:
    def __init__(self, api_key, ingest_url):
        self.api_key = api_key
        self.ingest_url = ingest_url.rstrip("/")

