import json
from difflib import get_close_matches
from typing import List, Optional

class Chatbot:
    def __init__(self, knowledge_base_path: str):
        self.knowledge_base_path = knowledge_base_path
        self.knowledge_base = self.load_knowledge_base(knowledge_base_path)

    def load_knowledge_base(self, file_path: str) -> dict:
        """Load the knowledge base from a JSON file."""
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {"questions": []}
        except json.JSONDecodeError:
            raise ValueError("Error decoding JSON from the knowledge base.")

    def save_knowledge_base(self):
        """Save the knowledge base back to the JSON file."""
        with open(self.knowledge_base_path, 'w') as file:
            json.dump(self.knowledge_base, file, indent=2)

    def find_best_match(self, user_question: str) -> Optional[str]:
        """Find the best match for the user's question."""
        questions = [q["question"] for q in self.knowledge_base["questions"]]
        matches = get_close_matches(user_question, questions, n=1, cutoff=0.6)
        return matches[0] if matches else None

    def get_answer_for_question(self, question: str) -> Optional[str]:
        """Retrieve the answer for a given question."""
        for q in self.knowledge_base["questions"]:
            if q["question"].lower() == question.lower():
                return q["answer"]
        return None

    def teach_new_answer(self, user_input: str) -> str:
        """Teach the chatbot a new answer for a given question."""
        new_answer = input("Type the answer: ")
        if new_answer and new_answer.lower() != 'skip':
            self.knowledge_base["questions"].append({"question": user_input, "answer": new_answer})
            self.save_knowledge_base()
            return "Thank you! I learned a new response!"
        return "Skipped learning a new response."
