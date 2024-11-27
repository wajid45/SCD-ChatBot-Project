from abc import ABC, abstractmethod

# Abstract Screen class
class Screen(ABC):
    @abstractmethod
    def display(self):
        pass

# Concrete Screen classes
class LoginScreen(Screen):
    def display(self):
        print("Displaying login screen")

class RegisterScreen(Screen):
    def display(self):
        print("Displaying register screen")

class ChatScreen(Screen):
    def display(self):
        print("Displaying chat screen")

# Factory Method for creating different screens
class ScreenFactory:
    @staticmethod
    def create_screen(screen_type: str) -> Screen:
        if screen_type == "login":
            return LoginScreen()
        elif screen_type == "register":
            return RegisterScreen()
        elif screen_type == "chat":
            return ChatScreen()
        else:
            raise ValueError(f"Unknown screen type: {screen_type}")

# Usage in the ChatbotApp class
class ChatbotApp:
    # ... existing code ...

    def create_screen(self, screen_type: str):
        screen = ScreenFactory.create_screen(screen_type)
        screen.display()

    def show_login(self):
        self.create_screen("login")
        # other login logic...
    
    def show_register(self):
        self.create_screen("register")
        # other register logic...
    
    def create_chatbot_interface(self):
        self.create_screen("chat")
        # other chatbot logic...
