import requests

class NameSearchModule:
    def __init__(self, name: str):
        self.name = name

    def run(self) -> dict:
        if not self.name:
            return {"error": "No name provided"}

        print(f"[🔎] Buscando información sobre '{self.name}' en la API de DuckDuckGo...")

        try:
            url = "https://api.duckduckgo.com/"
            params = {"q": self.name, "format": "json", "no_redirect": 1, "no_html": 1}
            res = requests.get(url, params=params, timeout=10)
            res.raise_for_status()

            data = res.json()
            links = []

            # Extrae URLs de los resultados relacionados
            if "RelatedTopics" in data:
                for item in data["RelatedTopics"]:
                    if isinstance(item, dict) and "FirstURL" in item:
                        links.append(item["FirstURL"])

            print(f"[✅] {len(links)} resultados encontrados.")
            return {"count": len(links), "links": links[:10]}

        except Exception as e:
            print(f"[⚠️] Error en NameSearchModule: {e}")
            return {"count": 0, "links": []}
