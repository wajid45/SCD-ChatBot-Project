from observer import Observable
from tkinter import simpledialog
from difflib import get_close_matches
from typing import List, Optional
import json

class Chatbot(Observable):
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Chatbot, cls).__new__(cls)
        return cls._instance

    def __init__(self, knowledge_base_path: str):
        if not hasattr(self, 'initialized'):  # Ensure initialization happens only once
            super().__init__()
            self.knowledge_base_path = knowledge_base_path
            self.knowledge_base = self.load_knowledge_base(knowledge_base_path)
            self.initialized = True

    def load_knowledge_base(self, file_path: str) -> dict:
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {"questions": []}
        except json.JSONDecodeError:
            raise ValueError("Error decoding JSON from the knowledge base.")

    def save_knowledge_base(self):
        with open(self.knowledge_base_path, 'w') as file:
            json.dump(self.knowledge_base, file, indent=2)

    def find_best_match(self, user_question: str, questions: List[str]) -> Optional[str]:
        matches = get_close_matches(user_question, questions, n=1, cutoff=0.6)
        return matches[0] if matches else None

    def get_answer_for_question(self, question: str) -> Optional[str]:
        for q in self.knowledge_base["questions"]:
            if q["question"].lower() == question.lower():
                return q["answer"]
        return None

    def teach_new_answer(self, user_input: str) -> str:
        new_answer = simpledialog.askstring("Input", "Type the answer or type 'skip' to skip:")
        if new_answer and new_answer.lower() != 'skip':
            self.knowledge_base["questions"].append({"question": user_input, "answer": new_answer})
            self.save_knowledge_base()
            self.notify_observers(f"New answer learned for: {user_input}")
            return "Thank you! I learned a new response!"
        return "Skipped learning a new response."
    