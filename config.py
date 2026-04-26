DB_CONFIG = {
    "host": "localhost",
    "port": "5433",
    "database": "Scan_db",
    "user": "postgres",
    "password": "Slp2003"
}

# Faster than llama3
OLLAMA_MODEL = "llama3"

# Keep scans fast and predictable by default. Set to True when you want
# optional LLM narrative synthesis on top of deterministic profiling.
ENABLE_LLM_SYNTHESIS = False
