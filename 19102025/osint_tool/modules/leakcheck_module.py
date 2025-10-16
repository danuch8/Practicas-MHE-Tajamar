import requests

class LeakCheckModule:
    def __init__(self, email: str):
        self.email = email

    def run(self) -> dict:
        if not self.email:
            return {"error": "No email provided"}

        url = "https://leakcheck.io/api/public"
        params = {"check": self.email}

        try:
            r = requests.get(url, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return {
                    "source": "leakcheck.io",
                    "query": data.get("query", self.email),
                    "found": data.get("found", False),
                    "sources": data.get("sources", []),
                }
            else:
                return {
                    "status": r.status_code,
                    "text": r.text[:300],
                    "source": "leakcheck.io"
                }
        except Exception as e:
            return {"error": str(e)}
