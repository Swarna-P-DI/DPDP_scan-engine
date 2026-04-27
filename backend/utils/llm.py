from backend.config import OLLAMA_MODEL

llm = None


def _get_llm():
    global llm
    if llm is None:
        from langchain_ollama import ChatOllama
        llm = ChatOllama(model=OLLAMA_MODEL)
    return llm


def invoke_llm(prompt: str) -> str:
    response = _get_llm().invoke(prompt)
    return response.content
