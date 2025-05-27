from pathlib import Path
import json
import sys
import threading
import subprocess

from firebase_admin import auth, credentials, initialize_app, firestore
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput

#detect if running from exe, find exe file path
if getattr(sys, 'frozen', False):
    base_dir = Path(sys._MEIPASS)
else:
    base_dir = Path(__file__).resolve().parent

#setup firebase variables
service_account_key_path = base_dir / "serviceAccountKey.json"
cred = credentials.Certificate(str(service_account_key_path))
initialize_app(cred)

#setup chatwizard directory
APP_DIR = Path().home() / ".ChatWizard"
CONFIG_FILE = APP_DIR / "config.json"
APP_DIR.mkdir(parents=True, exist_ok=True)

USERNAME = None

def get_message_history(user_id, contact_id):
    history_dir = APP_DIR / "message_history"
    history_dir.mkdir(exist_ok=True)
    chat_id = f"{min(user_id, contact_id)}_{max(user_id, contact_id)}"
    history_file = history_dir / f"{chat_id}.json"
    if not history_file.exists():
        return []
    with open(history_file, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_message_history(user_id, contact_id, history):
    history_dir = APP_DIR / "message_history"
    history_dir.mkdir(exist_ok=True)
    chat_id = f"{min(user_id, contact_id)}_{max(user_id, contact_id)}"
    history_file = history_dir / f"{chat_id}.json"
    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)

def get_contacts(user_id):
    history_dir = APP_DIR / "message_history"
    history_dir.mkdir(exist_ok=True)
    contacts = set()
    #find all conversatiosn in the history directory
    for file in history_dir.glob("*.json"):
        #get user and sender id, and add them as contacts.
        a, b = file.stem.split("_")
        if a == user_id:
            contacts.add(b)
        elif b == user_id:
            contacts.add(a)
    return list(contacts)

def start_kivy_is_stupid(username):
    #start listener
    subprocess.run(["python", "kivyisstupid.py", username], check=True)


class ConversationTile(BoxLayout):
    def __init__(self, name, last_message, **kwargs):
        super().__init__(orientation='vertical', size_hint_y=None, height=80, padding=5, **kwargs)
        #consversation name
        self.add_widget(Label(text=name, size_hint_y=None, height=24, bold=True))
        #last message in conversation
        self.add_widget(Label(text=last_message, size_hint_y=None, height=24, color=(0.5,0.5,0.5,1)))

class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        #username field
        self.username_input = TextInput(hint_text="Enter your username", size_hint=(1,None), height=40)
        
        #login button
        self.login_button = Button(text="Login", size_hint=(1,None), height=50)
        self.login_button.bind(on_press=self.go_to_messages)
        self.error_label = Label(text="", size_hint=(1,None), height=40)


        layout.add_widget(self.username_input)
        layout.add_widget(self.login_button)
        layout.add_widget(self.error_label)
        self.add_widget(layout)

    def go_to_messages(self, instance):
        global USERNAME
        USERNAME = self.username_input.text.strip()
        if not USERNAME:
            self.error_label.text = "Please enter a username."
            return

        self.manager.current = "messages"

        #start listener
        threading.Thread(target=start_kivy_is_stupid, args=(USERNAME,), daemon=True).start()


class MessageScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.root_layout = BoxLayout(orientation='horizontal', size_hint=(1,1))
        self.add_widget(self.root_layout)

        #conversation list
        self.conv_scroll = ScrollView(size_hint=(0.3,1))
        self.conv_list = BoxLayout(orientation='vertical', size_hint_y=None, spacing=10, padding=10)
        self.conv_list.bind(minimum_height=self.conv_list.setter('height'))
        self.conv_scroll.add_widget(self.conv_list)
        self.root_layout.add_widget(self.conv_scroll)

        #right side layout for chat and input
        self.right_layout = BoxLayout(orientation='vertical', size_hint=(0.7,1))
        self.root_layout.add_widget(self.right_layout)

        #chat history
        self.chat_pane = ScrollView(size_hint=(1,0.85))
        self.chat_list = BoxLayout(orientation='vertical', size_hint_y=None, spacing=5, padding=10)
        self.chat_list.bind(minimum_height=self.chat_list.setter('height'))
        self.chat_pane.add_widget(self.chat_list)
        self.right_layout.add_widget(self.chat_pane)

        #message input area
        self.input_layout = BoxLayout(orientation='horizontal', size_hint=(1,0.15), padding=10, spacing=10)
        self.message_input = TextInput(
            hint_text="Type your message here...",
            size_hint=(0.8,1),
            multiline=False
        )
        self.send_button = Button(
            text="Send",
            size_hint=(0.2,1)
        )
        self.send_button.bind(on_press=self.send_message)
        self.message_input.bind(on_text_validate=self.send_message)  # Send on Enter key
        
        self.input_layout.add_widget(self.message_input)
        self.input_layout.add_widget(self.send_button)
        self.right_layout.add_widget(self.input_layout)

        #refresh messages every second
        Clock.schedule_interval(self.update_conversations, 1)
        Clock.schedule_interval(self.refresh_chat_display,1 )
        self.active_conversation = None
    
    #update messages when message screen is entered.
    def on_enter(self):
        if USERNAME:
            self.update_conversations(0)

    def send_message(self, instance):
        if not self.active_conversation or not USERNAME:
            return
        
        message_text = self.message_input.text.strip()
        if not message_text:
            return
        
        #outgoing messages file
        message_file = APP_DIR / "outgoing_messages.json"
        if message_file.exists():
            with open(message_file, "r") as f:
                try:
                    messages = json.load(f)
                    if not isinstance(messages, list):
                        messages = []
                except json.JSONDecodeError:
                    messages = []
        else:
            messages = []
        
        #message info
        new_message = {
            "sender": USERNAME,
            "recipient": self.active_conversation,
            "message": message_text,
            "timestamp": Clock.get_time()
        }
        
        messages.append(new_message)
        
        with open(message_file, "w") as f:
            json.dump(messages, f, indent=2)

        #clear input
        self.message_input.text = ""
        
        #update chat display
        self.refresh_chat_display(0)

    def refresh_chat_display(self, dt):
        if not self.active_conversation:
            return
            
        self.chat_list.clear_widgets()
        history = get_message_history(USERNAME, self.active_conversation)
        
        if not history:
            self.chat_list.add_widget(Label(text="(no messages yet)", size_hint_y=None, height=30))
        else:
            for entry in history:
                sender = entry.get("sender", self.active_conversation)
                msg = entry["message"]
                lbl = Label(
                    text=f"[b]{sender}:[/b] {msg}",
                    markup=True,
                    size_hint_y=None,
                    height=30,
                    halign="left",
                    valign="middle"
                )
                lbl.text_size = (self.chat_list.width * 0.9, None)
                self.chat_list.add_widget(lbl)

        # scroll to bottom
        Clock.schedule_once(lambda dt: self.chat_pane.scroll_to(self.chat_list.children[0]), 0.1)

    def update_conversations(self,dt):
        if not USERNAME:
            return
        self.conv_list.clear_widgets()
        for contact in get_contacts(USERNAME):
            history = get_message_history(USERNAME, contact)
            last = history[-1]["message"] if history else "(no messages)"
            tile = ConversationTile(contact, last)
            tile.bind(on_touch_down=lambda inst, touch, t=tile: self.on_tile_click(t, touch))
            self.conv_list.add_widget(tile)

    def on_tile_click(self, tile, touch):
        if not tile.collide_point(*touch.pos):
            return
        convo_with = tile.children[1].text
        self.active_conversation = convo_with
        
        # refresh the chat display
        self.refresh_chat_display(0)


class ChatWizardApp(App):
    def build(self):
        Window.size = (800, 600)
        Window.minimum_width, Window.minimum_height = 400, 300

        sm = ScreenManager()
        sm.add_widget(RegisterScreen(name="register"))
        sm.add_widget(MessageScreen(name="messages"))
        return sm

if __name__ == '__main__':
    ChatWizardApp().run()