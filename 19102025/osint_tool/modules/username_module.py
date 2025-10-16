import subprocess

class UsernameModule:
    def __init__(self, username: str, sherlock_path: str = "sherlock"):
        self.username = username
        self.sherlock_path = sherlock_path

    def run(self) -> dict:
        if not self.username:
            return {"error": "No username provided"}
        try:
            cmd = [self.sherlock_path, self.username]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {"exit_code": proc.returncode, "output": proc.stdout[:2000]}
        except FileNotFoundError:
            return {"error": "Sherlock not found. Install or provide correct path."}
        except Exception as e:
            return {"error": str(e)}
