import re
import bcrypt
import mysql.connector
import tkinter as tk
from tkinter import scrolledtext, messagebox
from PIL import Image, ImageTk
import logging
from main import Chatbot

logging.basicConfig(level=logging.DEBUG)

class ChatbotApp:
    def __init__(self, chatbot):
        self.chatbot = chatbot
        self.chatbot.register_observer(self)
        self.logged_in = False
        self.username = ""

        try:
            self.db_connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  
                database="chatbot_db"
            )
            self.db_cursor = self.db_connection.cursor()
            logging.info("Database connection established.")
        except mysql.connector.Error as err:
            logging.error(f"Error connecting to database: {err}")
            messagebox.showerror("Database Connection Error", str(err))
            exit()

        self.root = tk.Tk()
        self.root.title("Chatbot")
        self.root.geometry("800x600")  # Reduced window size
        self.create_login_screen()

    @staticmethod
    def validate_password(password):
        pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+=-]).{6,}$'
        return re.match(pattern, password)

    @staticmethod
    def validate_username(username):
        pattern = r'^[A-Za-z0-9]+$'
        return re.match(pattern, username)

    def validate_user_info(self, username, password):
        if not username or not password:
            return "Username and password fields cannot be empty."
        if not self.validate_username(username):
            return "Username can only contain alphabets and numbers."
        if not self.validate_password(password):
            return ("Password must be at least 6 characters long and include at least "
                    "1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character.")
        return None

    def show_message(self, title, message, is_error=False):
        if is_error:
            messagebox.showerror(title, message, icon='warning')
        else:
            messagebox.showinfo(title, message, icon='info')

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    def check_password(self, plain_password, hashed_password):
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

    def register_user(self):
        username_info = self.username.get().strip()
        password_info = self.password.get()
        confirm_password_info = self.confirm_password.get()

        if not username_info:
            return self.show_message("Error", "Username cannot be empty.", True)

        if password_info != confirm_password_info:
            return self.show_message("Error", "Passwords do not match.", True)

        validation_error = self.validate_user_info(username_info, password_info)
        if validation_error:
            return self.show_message("Error", validation_error, True)

        try:
            self.db_cursor.execute("SELECT * FROM users WHERE username = %s", (username_info,))
            if self.db_cursor.fetchone():
                return self.show_message("Error", "Username already exists. Please choose a different username.", True)

            hashed_password = self.hash_password(password_info)
            self.db_cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                                   (username_info, hashed_password))
            self.db_connection.commit()
            self.show_message("Registration", "Registration Successful")
            self.show_login()
        except mysql.connector.Error as e:
            logging.error(f"Failed to register user: {e}")
            self.show_message("Error", f"Failed to register user: {e}", True)

    def set_background(self, image_path):
        # Set background image
        try:
            img = Image.open(image_path)
            img = img.resize((800, 600), Image.ANTIALIAS)
            photo = ImageTk.PhotoImage(img)

            bg_label = tk.Label(self.root, image=photo)
            bg_label.image = photo
            bg_label.place(relwidth=1, relheight=1)  # Cover entire window
        except Exception as e:
            logging.error(f"Error loading background image: {e}")
            messagebox.showerror("Image Load Error", "Failed to load background image.")


    def login_verify(self):
        username1 = self.username_verify.get().strip()
        password1 = self.password_verify.get()

        try:
            self.db_cursor.execute("SELECT username, password FROM users WHERE username = %s", (username1,))
            user = self.db_cursor.fetchone()

            if user:
                if self.check_password(password1, user[1].encode('utf-8')):
                    self.logged_in = True
                    self.username = user[0]
                    self.create_chatbot_interface()
                    self.show_message("Welcome", f"Welcome, {self.username}!")
                else:
                    self.show_message("Error", "Incorrect password. Please try again.", True)
            else:
                self.show_message("Error", "Username not found. Please check your username.", True)

        except mysql.connector.Error as e:
            logging.error(f"Failed to login: {e}")
            self.show_message("Error", f"Failed to login: {e}", True)

    def add_image(self, image_path, width, height):
        try:
            img = Image.open(image_path)
            img = img.resize((width, height), Image.ANTIALIAS)
            photo = ImageTk.PhotoImage(img)
            
            label = tk.Label(self.root, image=photo)
            label.image = photo
            label.pack(pady=15)
        except Exception as e:
            logging.error(f"Error loading image: {e}")
            messagebox.showerror("Image Load Error", "Failed to load image.")

    def create_login_screen(self):
        self.clear_widgets()
        tk.Label(self.root, text="Select Your Choice", bg="grey", width="135", height="2", font=("Calibri", 14)).pack(pady=15)

        # Add Login Icon Image
        self.add_image("assets/images/login_icon.png", 80, 80)
        # Add Login Background Image
        self.set_background("assets/images/login_background.jpg")

        tk.Button(self.root, text="Login", height="2", width="30", font=("Arial", 14), command=self.show_login).pack(pady=20)
        tk.Button(self.root, text="Register", height="2", width="30", font=("Arial", 14), command=self.show_register).pack(pady=20)

    def clear_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_widgets()
        tk.Label(self.root, text="Login", font=("Arial", 20)).pack(pady=20)

        # Add Login Icon Image
        self.add_image("assets/images/login_icon.png", 80, 80)
        # Add Background Image
        self.set_background("assets/images/login_background.jpg")


        self.username_verify = tk.StringVar()
        self.password_verify = tk.StringVar()

        tk.Label(self.root, text="Username * ", font=("Arial", 14)).pack(pady=10)
        tk.Entry(self.root, textvariable=self.username_verify, font=("Arial", 14), width=30).pack(pady=10)

        tk.Label(self.root, text="Password * ", font=("Arial", 14)).pack(pady=10)
        tk.Entry(self.root, textvariable=self.password_verify, show='*', font=("Arial", 14), width=30).pack(pady=10)

        tk.Button(self.root, text="Login", font=("Arial", 14), width=15, command=self.login_verify).pack(pady=20)
        tk.Button(self.root, text="Register", font=("Arial", 14), width=15, command=self.show_register).pack(pady=20)

    def show_register(self):
        self.clear_widgets()
        tk.Label(self.root, text="Register", font=("Arial", 20)).pack(pady=20)

        # Add Signup Icon Image
        self.add_image("assets/images/signup_icon.png", 80, 80)
        # Add Backgroung Image
        self.set_background("assets/images/login_background.jpg")

        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()

        tk.Label(self.root, text="Username : ", font=("Arial", 14)).pack(pady=10)
        tk.Entry(self.root, textvariable=self.username, font=("Arial", 14), width=30).pack(pady=10)

        tk.Label(self.root, text="Password : ", font=("Arial", 14)).pack(pady=10)
        password_entry = tk.Entry(self.root, textvariable=self.password, show='*', font=("Arial", 14), width=30)
        password_entry.pack(pady=10)

        self.password_validation_label = tk.Label(self.root, text="", fg="red", anchor='center', font=("Arial", 12))

        password_entry.bind("<KeyRelease>", self.validate_password_input)

        tk.Label(self.root, text="Confirm Password * ", font=("Arial", 14)).pack(pady=10)
        tk.Entry(self.root, textvariable=self.confirm_password, show='*', font=("Arial", 14), width=30).pack(pady=10)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=30)
        tk.Button(button_frame, text="Register", font=("Arial", 14), width=15, command=self.register_user).pack(side=tk.LEFT, padx=15)
        tk.Button(button_frame, text="Back to Login", font=("Arial", 14), width=15, command=self.show_login).pack(side=tk.LEFT, padx=15)


    def validate_password_input(self, event=None):
        password = self.password.get()
        if self.validate_password(password):
            self.password_validation_label.config(text="Password is valid!", fg="green")
        else:
            self.password_validation_label.config(text=( 
                "Password must be at least 6 characters long, "
                "and include at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character."
            ))

    def create_chatbot_interface(self):
        self.clear_widgets()

        # Set the window title
        self.root.title("Finess and Wellness Chatbot")

        # Add a logo at the top of the window
        logo = Image.open("assets/images/app_logo.png") 
        logo = logo.resize((100, 100), Image.ANTIALIAS)
        logo_photo = ImageTk.PhotoImage(logo)

        logo_label = tk.Label(self.root, image=logo_photo)
        logo_label.image = logo_photo 
        logo_label.pack(pady=10) 
        
        # Display the title label
        title_label = tk.Label(self.root, text="Finess and Wellness Chatbot", font=("Arial", 24, "bold"), fg="darkblue")
        title_label.pack(pady=10)  # Add some padding between the logo and title

        # Create the output area (chat display)
        self.output_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state='normal', height=15, width=60, font=("Arial", 14))
        self.output_area.pack(pady=10)
        self.output_area.insert(tk.END, "Welcome to the Chatbot! Type 'quit' to exit.\n")

        # Create the user input entry box
        self.user_input_entry = tk.Entry(self.root, width=40, font=("Arial", 14))
        self.user_input_entry.pack(pady=10)
        self.user_input_entry.bind("<Return>", lambda event: self.on_send())

        # Create the Send button
        send_button = tk.Button(self.root, text="Send", font=("Arial", 14), command=self.on_send)
        send_button.pack(pady=20)
    def chatbot_response(self, user_input: str):
        best_match = self.chatbot.find_best_match(user_input, [q["question"] for q in self.chatbot.knowledge_base["questions"]])

        if best_match:
            answer = self.chatbot.get_answer_for_question(best_match)
            self.output_area.insert(tk.END, f'Bot: {answer}\n')
        else:
            self.output_area.insert(tk.END, "Bot: I don't know the answer. Can you teach me?\n")
            teach_response = self.chatbot.teach_new_answer(user_input)
            if teach_response:
                self.output_area.insert(tk.END, f'Bot: {teach_response}\n')

    def on_send(self):
        user_input = self.user_input_entry.get().strip()
        if user_input.lower() == "quit":
            self.root.quit()
        else:
            self.output_area.insert(tk.END, f'You: {user_input}\n')
            self.chatbot_response(user_input)
            self.user_input_entry.delete(0, tk.END)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    chatbot = Chatbot('knowledge_base.json')
    app = ChatbotApp(chatbot)
    app.run()
