import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Load the Gemini API key from the environment variable "GEMINI_API_KEY"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")