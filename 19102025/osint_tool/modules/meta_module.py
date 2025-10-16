import requests
from bs4 import BeautifulSoup

class MetaModule:
    def __init__(self, domain: str):
        self.domain = domain

    def run(self) -> dict:
        if not self.domain:
            return {"error": "No domain provided"}
        url = self.domain if self.domain.startswith("http") else f"http://{self.domain}"
        try:
            r = requests.get(url, timeout=8, headers={"User-Agent": "OSINTTool/1.0"})
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else None
            desc_tag = soup.find("meta", attrs={"name": "description"})
            desc = desc_tag["content"].strip() if desc_tag and desc_tag.get("content") else None
            return {"url": url, "status_code": r.status_code, "title": title, "description": desc}
        except Exception as e:
            return {"error": str(e)}
