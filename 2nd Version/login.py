import tkinter as tk
from tkinter import messagebox
from main import Chatbot

# Hardcoded credentials (could be replaced with a more secure method)
USERNAME = "admin"
PASSWORD = "password123"

class LoginPage(tk.Tk):
    def __init__(self, chatbot_class):
        super().__init__()
        self.chatbot_class = chatbot_class
        self.title("Login Page")
        self.geometry("300x200")

        # Create the username and password labels and entry fields
        self.username_label = tk.Label(self, text="Username:")
        self.username_label.pack(pady=5)

        self.username_entry = tk.Entry(self)
        self.username_entry.pack(pady=5)

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack(pady=5)

        # Login button
        self.login_button = tk.Button(self, text="Login", command=self.login)
        self.login_button.pack(pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == USERNAME and password == PASSWORD:
            messagebox.showinfo("Login Success", "Welcome!")
            self.open_chatbot()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def open_chatbot(self):
        """Create and open the chatbot interface after successful login."""
        knowledge_base_path = "knowledge_base.json"  # Set path to the knowledge base file
        chatbot = self.chatbot_class(knowledge_base_path)
        self.destroy()  # Close the login window
        ChatbotWindow(chatbot).mainloop()

class ChatbotWindow(tk.Tk):
    def __init__(self, chatbot):
        super().__init__()
        self.chatbot = chatbot
        self.title("Chatbot Interface")
        self.geometry("400x400")

        self.chat_log = tk.Text(self, state=tk.DISABLED, height=15, width=50)
        self.chat_log.pack(pady=10)

        self.entry_field = tk.Entry(self, width=50)
        self.entry_field.pack(pady=10)

        self.send_button = tk.Button(self, text="Send", command=self.send_message)
        self.send_button.pack(pady=5)

    def send_message(self):
        user_message = self.entry_field.get()
        if user_message:
            self.display_message(f"You: {user_message}")
            self.entry_field.delete(0, tk.END)
            self.get_response(user_message)

    def display_message(self, message):
        self.chat_log.config(state=tk.NORMAL)
        self.chat_log.insert(tk.END, message + "\n")
        self.chat_log.config(state=tk.DISABLED)

    def get_response(self, user_message):
        # Look for the best match for the user's question
        best_match = self.chatbot.find_best_match(user_message)

        if best_match:
            answer = self.chatbot.get_answer_for_question(best_match)
            self.display_message(f"Chatbot: {answer}")
        else:
            self.display_message("Chatbot: I don't know the answer to that.")
            # Optionally, offer to teach the chatbot a new answer
            if messagebox.askyesno("Teach the chatbot", "Would you like to teach me an answer?"):
                self.chatbot.teach_new_answer(user_message)

if __name__ == "__main__":
    app = LoginPage(Chatbot)
    app.mainloop()
