import sqlite3
from openai import OpenAI
import time
from datetime import datetime
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


LLM_MODEL=""
DB_PATH = ""
OPENAI_CLIENT = OpenAI(
    api_key= "", 
)

MAX_TOKEN=-1
RESULT_TABLE = "final_result"


PROMPT_TEMP = '''
Analyze the following Android app log to check if the application may print Personally Identifiable Information (PII) at runtime. Specifically, look for <VARIABLE_PLACEHOLDER> entries that could represent any of the following types of PII:
	•	Device Serial Number
	•	GPS Coordinates
	•	SSID
	•	BSSID
	•	IMEI
	•	Phone Number
	•	Email
	•	AAID (Advertising ID)
	•	MAC Address
	•	IP Address

Analysis Requirements:
	1.	Only consider PII as being printed if you see <VARIABLE_PLACEHOLDER> in the log.
	2.	If <VARIABLE_PLACEHOLDER> is present, analyze the surrounding context to determine if it clearly represents one of the PII categories above.
	3.	If <VARIABLE_PLACEHOLDER> does not appear or there is no clear indication of PII, conclude that the application does not print PII for that category.
    4.  Avoid over-interpreting or making assumptions. If there isn’t enough context to link "<VARIABLE_PLACEHOLDER>" to a specific PII type, mark it as not printed.
Output Format:
Provide your findings in JSON format, with each PII type as a key and two fields:
	•	printed (true or false)
	•	explain (a brief explanation detailing why you made this determination)

Log Content:
<content>

'''

def connect_db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def create_response_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {RESULT_TABLE} (
            content TEXT PRIMARY KEY,
            is_contained_pii INT NOT NULL,
            pii_type TEXT,
            model TEXT NOT NULL,
            max_tokens INT NOT NULL,
            input_token INT NOT NULL,
            output_token INT NOT NULL,
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            is_bad_response INT NOT NULL,
            is_fp INT,
            is_fn INT
        )
    """)
    conn.commit()
    conn.close()

def fetch_new_contents():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT DISTINCT p.content
        FROM possible_output p
        LEFT JOIN {RESULT_TABLE} f ON p.content = f.content
        WHERE f.content IS NULL
        ORDER BY p.content
    """)
    results = [row[0] for row in cursor.fetchall()]
    conn.close()
    return results

def save_response(content, response, input_token, output_token, input_prompt):
    conn = connect_db()
    cursor = conn.cursor()
    is_contained_pii = 0
    pii_types = "" 
    is_bad_response = 0
    
    try:
        match = re.search(r'```json\n(.*?)\n```', response, re.DOTALL)
        if match:
            json_str = match.group(1)
            try:
                pii_data = json.loads(json_str)
                is_contained_pii = any(value["printed"] for value in pii_data.values())
                pii_types = ", ".join([key for key, value in pii_data.items() if value["printed"]])
            except json.JSONDecodeError as e:
                is_bad_response = 1
        else:
            try:
                pii_data = json.loads(response)
                is_contained_pii = any(value["printed"] for value in pii_data.values())
                pii_types = ", ".join([key for key, value in pii_data.items() if value["printed"]])
            except json.JSONDecodeError as e:
                is_bad_response = 1
    
        cursor.execute(f"""
            INSERT INTO {RESULT_TABLE} 
            (content, is_contained_pii, pii_type, model, max_tokens, input_token, output_token, prompt, response, is_bad_response, is_fp, is_fn) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (content, int(is_contained_pii), pii_types, LLM_MODEL, MAX_TOKEN, input_token, output_token, input_prompt, response, is_bad_response, None, None))
        
        conn.commit()
    except Exception as ex:
        print(f"Exception SQL : {ex}")
    finally:
        conn.close() 

def analyze(content):
    try:
        prompt = PROMPT_TEMP.replace('<content>', content)
        response = OPENAI_CLIENT.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )   
        response_dict = response.model_dump()
        input_token = response_dict["usage"]["prompt_tokens"]
        output_token = response_dict["usage"]["completion_tokens"]
        response_text = response_dict["choices"][0]["message"]["content"].strip()
        
        return response_text, input_token, output_token, prompt
    except Exception as e:
        print(f"ChatGPT API Error: {e}")
        return None, None, None, None

def process_content(content):
    print(f"Analyzing Log: {content}\n")
    response_text, input_token, output_token, input_prompt = analyze(content)
    if response_text:
        save_response(content, response_text, input_token, output_token, input_prompt)

def main(thread_count=5):
    create_response_table()
    new_contents = fetch_new_contents()
    
    if new_contents:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            executor.map(process_content, new_contents)

if __name__ == "__main__":
    main(thread_count=88)