from rich.text import Text

def log_detail(hash_val: str, path: str, size: int) -> Text:
    return Text(f"📜 {hash_val} ({size} chars) from {path}", style="yellow")
