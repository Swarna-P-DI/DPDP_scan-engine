import json

def safe_json_parse(text):
    try:
        return json.loads(text)
    except:
        return {
            "raw_output": text,
            "error": "Invalid JSON from LLM"
        }