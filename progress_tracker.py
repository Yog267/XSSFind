progress_messages = []  # List to hold progress messages

def add_message(message):
    progress_messages.append(message)

def get_messages():
    return progress_messages

def clear_messages():
    global progress_messages
    progress_messages = []
