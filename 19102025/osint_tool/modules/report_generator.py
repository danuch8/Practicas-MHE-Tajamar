import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, results: dict, basename: str = "report"):
        self.results = results
        self.basename = basename

    def save_json(self):
        fname = f"{self.basename}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        return fname

    def save_html(self):
        fname = f"{self.basename}.html"
        html = [
            "<html><head><meta charset='utf-8'><title>OSINT Report</title></head><body>",
            f"<h1>OSINT Report ({datetime.utcnow().isoformat()} UTC)</h1>"
        ]
        for key, val in self.results.items():
            html.append(f"<h2>{key}</h2><pre>{json.dumps(val, indent=2, ensure_ascii=False)}</pre>")
        html.append("</body></html>")
        with open(fname, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        return fname
