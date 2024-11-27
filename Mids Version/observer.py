# observer.py
class Observable:
    def __init__(self):
        self._observers = []  # List of registered observers

    def register_observer(self, observer):
        """Register an observer."""
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer):
        """Unregister an observer."""
        if observer in self._observers:
            self._observers.remove(observer)

    def notify_observers(self, message):
        """Notify all registered observers with the given message."""
        for observer in self._observers:
            observer.update(message)
