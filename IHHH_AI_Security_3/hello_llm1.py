# hello_llm.py

# 라이브러리 설치 필요
# pip install openai python-dotenv

from openai import OpenAI
from dotenv import load_dotenv

# .env 파일의 환경변수(API키) 불러오기
load_dotenv()

# OPENAI_API 키를 자동으로 사용한다
client = OpenAI()


# 사용자의 입력
user_input = input("user prompt: ")

# LLM에게 입력 전달
response = client.responses.create(
        model = "gpt-5.5",
        input = user_input
)

print(f"{response}\n")
print(f"LLM: {response.output_text}\n\n")