from openai import OpenAI
from openai.types.chat import ChatCompletion
from dotenv import load_dotenv
import os
import json

load_dotenv()
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPEN_ROUTER_KEY"),
)

def ask_llm(message: str) -> ChatCompletion:
    response = client.chat.completions.create(
        model=os.getenv("LLM_MODEL"),
        messages=[
            {
                "role": "system", 
                "content": """your job is to guess if the following message is a phishing message or not.
                the messages come from someone phone, In both English and Hebrew. and can be from any app.

                answer only in the following format: {"confidence":<confidence_score>"}"""
            },
            {
                "role": "user", 
                "content": f"is this a phishing message?\n{message}"
            }
        ]
    )

    return response

def parse_llm_response(response: ChatCompletion):
    content = response.choices[0].message.content
    print("LLM response content:", content)
    try:
        data = json.loads(content)
        confidence = data.get("confidence", 0.0)
        return float(confidence)
    except (json.JSONDecodeError, ValueError, TypeError):
        return 0.0
    
def check_message_with_llm(message: str):
    response = None  
    CONFIDENCE_THRESHOLD = 0.7

    try:
        response = ask_llm(message)
    except Exception as e:
        print("Error communicating with LLM:", e)
        return 0.0
    
    confidence = parse_llm_response(response)

    return confidence >= CONFIDENCE_THRESHOLD, confidence
    
    
def main():
    phish_msg = """wel01.us/r/rest05 WELLS FARGO(CS):Profile locked because of unusual activities, kindly restore.Reply STOP to unsubscribe"""
    regular_msg = """שלום, הזמנתך מס׳ 259 מGiraffe רמת החייל מוכנה. מהיום אפשר להזמין באפליקציה שלנו ולהתחיל לצבור הטבות במועדון הלקוחות! נכנסים לעמוד המסעדה באפליקציית NONO-GROUP להורדה: https://tbit.be/nKoiVz"""

    jerbi_msg = """שלום רב,
נבקש לעדכנך כי עליך להסדיר עוד היום את חובך לכביש 6 , על מנת למנוע הטלת עיקולים או הגבלות.
לפרטים נוספים אנא לחץ על הקישור:

snip.ly/kivish6-payment"""

    is_phish, confidence = check_message_with_llm(jerbi_msg)
    if is_phish:
        print(f"The message is likely a phishing attempt. confidence: {confidence}")
    else:
        print(f"The message is likely safe. confidence: {confidence}")

if __name__ == "__main__":
    main()