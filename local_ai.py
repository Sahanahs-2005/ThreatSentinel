import json
import urllib.request
import urllib.error


OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3.2:1b"


def get_ai_response(message):
    """Send a message to the locally running Ollama model."""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {
                "role": "user",
                "content": message
            }
        ],
        "stream": False
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.loads(response.read().decode("utf-8"))

        return result["message"]["content"]

    except urllib.error.URLError as error:
        return f"AI connection error: {error}"
    except (KeyError, json.JSONDecodeError) as error:
        return f"Unexpected AI response: {error}"