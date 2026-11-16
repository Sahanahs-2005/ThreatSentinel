import os

from dotenv import load_dotenv
from google import genai


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

client = (
    genai.Client(api_key=API_KEY)
    if API_KEY
    else None
)


def get_ai_response(prompt):
    if client is None:
        raise RuntimeError(
            "GEMINI_API_KEY is missing from the .env file."
        )

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )

    if not response.text:
        raise RuntimeError("Gemini returned an empty response.")

    return response.text