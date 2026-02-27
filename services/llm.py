# services/llm.py
import os
try:
    import openai
except Exception:
    openai = None

OPENAI_KEY = os.getenv("OPENAI_API_KEY")

def one_line_summary(text: str) -> str:
    if openai is None or not OPENAI_KEY:
        return None
    openai.api_key = OPENAI_KEY
    prompt = f"Қысқаша бір сөйлемде: бұл бет неге қауіпті болуы мүмкін? Мәтін: {text[:2000]}"
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-4o-mini", messages=[{"role":"user","content":prompt}], max_tokens=40, temperature=0.0
        )
        return resp["choices"][0]["message"]["content"].strip()
    except Exception:
        return None
