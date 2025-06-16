from pathlib import Path
import json
import sys
import threading
import subprocess
import tkinter
import tkinter as tk 
from tkinter import filedialog
import time
from pytube import YouTube
import webbrowser

from firebase_admin import auth, credentials, initialize_app, firestore

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.textinput import TextInput
from kivy.uix.switch import Switch
from kivy.app import App
from kivy.uix.floatlayout import FloatLayout
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.filechooser import FileChooser
from kivy.uix.image import Image as KivyImage
from kivy.uix.videoplayer import VideoPlayer
from kivy.uix.gridlayout import GridLayout
import os
import base64
from PIL import Image
import io
import re

THEMES = {
    'light': {
        'window_bg': (1, 1, 1, 1),
        'text_color': (0, 0, 0, 1),
        'secondary_text': (0.3, 0.3, 0.3, 1),
        'button_bg': (0.9, 0.9, 0.9, 1),
        'button_text': (0, 0, 0, 1),
        'input_bg': (1, 1, 1, 1),
        'input_text': (0, 0, 0, 1),
    },
    'dark': {
        'window_bg': (0.1, 0.1, 0.1, 1),
        'text_color': (1, 1, 1, 1),
        'secondary_text': (0.7, 0.7, 0.7, 1),
        'button_bg': (0.2, 0.2, 0.2, 1),
        'button_text': (1, 1, 1, 1),
        'input_bg': (0.2, 0.2, 0.2, 1),
        'input_text': (1, 1, 1, 1),
    }
}

# detect if running from exe, find exe file path
if getattr(sys, 'frozen', False):
    base_dir = Path(sys._MEIPASS)
else:
    base_dir = Path(__file__).resolve().parent

# setup firebase variables
service_account_key_path = base_dir / "serviceAccountKey.json"
cred = credentials.Certificate(str(service_account_key_path))
initialize_app(cred)

# setup chatwizard directory
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

def get_all_users():
    db = firestore.client()
    users = db.collection("users").stream()
    return [user.id for user in users]

def get_contacts(user_id):
    history_dir = APP_DIR / "message_history"
    history_dir.mkdir(exist_ok=True)
    contacts = set()
    for file in history_dir.glob("*.json"):
        a, b = file.stem.split("_")
        if a == user_id:
            contacts.add(b)
        elif b == user_id:
            contacts.add(a)
    return list(contacts)

def start_kivy_is_stupid(username):
    if getattr(sys, 'frozen', False):
        base_dir = Path(sys.executable).parent
    else:
        base_dir = Path(__file__).resolve().parent
    kivy_file = base_dir / "kivyisstupid.py"
    subprocess.run([sys.executable, str(kivy_file), username], check=True)

class ConversationTile(BoxLayout):
    def __init__(self, name, last_message, **kwargs):
        super().__init__(orientation='vertical', size_hint_y=None, height=80, padding=5, **kwargs)
        app = App.get_running_app()
        theme = app.current_theme

        lbl_name = Label(
            text=name,
            size_hint_y=None,
            height=24,
            bold=True,
            color=theme['text_color']
        )
        lbl_last = Label(
            text=last_message,
            size_hint_y=None,
            height=24,
            color=theme['secondary_text']
        )
        self.add_widget(lbl_name)
        self.add_widget(lbl_last)

class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        app = App.get_running_app()
        theme = app.current_theme

        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.username_input = TextInput(
            hint_text="Enter your username",
            size_hint=(1, None),
            height=40,
            background_color=theme['input_bg'],
            foreground_color=theme['input_text']
        )

        self.login_button = Button(
            text="Login",
            size_hint=(1, None),
            height=50,
            background_color=theme['button_bg'],
            color=theme['button_text']
        )
        self.login_button.bind(on_press=self.go_to_messages)

        self.error_label = Label(
            text="",
            size_hint=(1, None),
            height=40,
            color=theme['secondary_text']
        )

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
        threading.Thread(target=start_kivy_is_stupid, args=(USERNAME,), daemon=True).start()

class MessageScreen(Screen):
    EMOJI_LIST = [':)', ':(', ':|', ';)', ':O', ':/']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        app = App.get_running_app()
        theme = app.current_theme

        self.root_layout = BoxLayout(orientation='vertical', size_hint=(1, 1))
        self.add_widget(self.root_layout)

        top_bar = BoxLayout(size_hint=(1, 0.05), padding=5, spacing=5)
        top_bar.canvas.before.clear()

        lbl_mode = Label(
            text="Dark Mode:",
            size_hint=(0.2, 1),
            color=theme['text_color']
        )
        self.switch = Switch(
            active=(app.theme_name == 'dark'),
            size_hint=(0.1, 1)
        )

        self.switch.bind(active=self.on_theme_switch)
        top_bar.add_widget(lbl_mode)
        top_bar.add_widget(self.switch)
        top_bar.add_widget(Label(size_hint=(0.7, 1)))
        self.root_layout.add_widget(top_bar)

        content_area = BoxLayout(orientation='horizontal', size_hint=(1, 0.95))
        self.root_layout.add_widget(content_area)

        # conversation list
        self.conv_scroll = ScrollView(size_hint=(0.3, 1))
        self.conv_list = BoxLayout(orientation='vertical', size_hint_y=None, spacing=10, padding=10)
        self.conv_list.bind(minimum_height=self.conv_list.setter('height'))
        self.conv_scroll.add_widget(self.conv_list)
        content_area.add_widget(self.conv_scroll)

        # new conversation button
        self.new_conversation_button = Button(
            text=" New \n chat",
            size_hint=(0.2, 1),
            background_color=theme['button_bg'],
            color=theme['button_text']
        )

        self.popup = Popup(
            title='select user(s)',
            content=BoxLayout(orientation='vertical', size_hint=(1, 0.15), padding=10, spacing=10),
            size_hint=(None, None), size=(400, 400)
        )
        self.user_input = TextInput(
            hint_text="enter user(s) for conversation, seperated by ','",
            multiline=False,
            background_color=theme['input_bg'],
            foreground_color=theme['input_text']
        )
        self.user_input.bind(on_text_validate=self.new_conversation)
        self.popup.content.add_widget(self.user_input)
        self.new_conversation_button.bind(on_press=self.popup.open)
        # content_area.add_widget(self.new_conversation_button)

        self.right_layout = BoxLayout(orientation='vertical', size_hint=(0.7, 1))
        

        self.chat_pane = ScrollView(size_hint=(1, 0.85))
        self.chat_list = BoxLayout(orientation='vertical', size_hint_y=None, spacing=5, padding=10)
        self.chat_list.bind(minimum_height=self.chat_list.setter('height'))
        self.chat_pane.add_widget(self.chat_list)
        self.right_layout.add_widget(self.chat_pane)
        content_area.add_widget(self.right_layout)

        
        self.attach_button = Button(
            text="+",
            size_hint=(0.2, 1),
            background_color=theme['button_bg'],
            color=theme['button_text']
        )

        self.file_selection_popup = Popup(
            title='select image/video',
            content=BoxLayout(orientation='vertical', size_hint=(1, 0.15), padding=10, spacing=10),
            size_hint=(None, None), size=(400, 400)
        )

        self.user_filename_input = TextInput(
            hint_text="enter filename",
            multiline=False,
            background_color=theme['input_bg'],
            foreground_color=theme['input_text']
        )

        self.user_filename_input.bind(on_text_validate=self.send_image)
        self.file_selection_popup.content.add_widget(self.user_filename_input)
        self.attach_button.bind(on_press=self.file_selection_popup.open)


        self.emoji_picker = Popup(
            title="Choose reaction",
            size_hint=(None, None),
            size=(300, 200)
        )
        grid = GridLayout(cols=3, spacing=10, padding=10)
        for emo in self.EMOJI_LIST:
            btn = Button(text=emo, font_size=24)
            btn.bind(on_press=lambda btn, e=emo: self._on_emoji_selected(e))
            grid.add_widget(btn)
        self.emoji_picker.add_widget(grid)

        self._pending_reaction_target = None



        self.input_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.15), padding=10, spacing=10)
        self.message_input = TextInput(
            hint_text="Type your message here...",
            size_hint=(0.8, 1),
            multiline=False,
            background_color=theme['input_bg'],
            foreground_color=theme['input_text']
        )
        self.send_button = Button(
            text="Send",
            size_hint=(0.2, 1),
            background_color=theme['button_bg'],
            color=theme['button_text']
        )
        self.send_button.bind(on_press=self.send_message)
        self.message_input.bind(on_text_validate=self.send_message)

        self.input_layout.add_widget(self.new_conversation_button)
        self.input_layout.add_widget(self.attach_button)
        self.input_layout.add_widget(self.message_input)
        self.input_layout.add_widget(self.send_button)
        self.right_layout.add_widget(self.input_layout)
       

        Clock.schedule_interval(self.update_conversations, 1)
        Clock.schedule_interval(self.refresh_chat_display, 1)

        self.active_conversation = None

    def send_image(self,instance):
        filename = self.user_filename_input.text.strip()
        if os.path.exists(filename):
            print(f"{filename} exists")
            if filename.endswith(".jpg"):
                print("is jpg")
                if not self.active_conversation or not USERNAME:
                    return
                
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

                new_message = {
                    "sender": USERNAME,
                    "recipient": self.active_conversation,
                    "message": None,
                    "timestamp": Clock.get_time(),
                    "image": filename
                }

                messages.append(new_message)
                with open(message_file, "w") as f:
                    json.dump(messages, f, indent=2)

                self.message_input.text = ""
                self.refresh_chat_display(0)
            else:
                print("Not JPG")
                return

        else:
            print(f"{filename} DNE")
            return

    def on_enter(self):
        if USERNAME:
            self.update_conversations(0)

    def on_theme_switch(self, switch_instance, value):
        app = App.get_running_app()
        app.theme_name = 'dark' if value else 'light'
        app.current_theme = THEMES[app.theme_name]
        app.apply_theme()

    def new_conversation(self, instance):
        if not USERNAME:
            return

        users = self.user_input.text.strip()
        if not users:
            return

        if users not in get_all_users():
            return

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

        new_message = {
            "sender": USERNAME,
            "recipient": users,
            "message": "Hello! It is so good to meet you! Lets chat!",
            "timestamp": Clock.get_time(),
            "image": None
        }

        messages.append(new_message)
        with open(message_file, "w") as f:
            json.dump(messages, f, indent=2)

        self.message_input.text = ""
        self.refresh_chat_display(0)



    
    def send_message(self, instance):
        if not self.active_conversation or not USERNAME:
            return

        message_text = self.message_input.text.strip()
        if not message_text:
            return

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

        new_message = {
            "sender": USERNAME,
            "recipient": self.active_conversation,
            "message": message_text,
            "timestamp": Clock.get_time(),
            "image": None
        }

        messages.append(new_message)
        with open(message_file, "w") as f:
            json.dump(messages, f, indent=2)

        self.message_input.text = ""
        self.refresh_chat_display(0)

    def get_youtube_url(self, text):

        regex = re.compile(
            r'(https?://(?:www\.)?'
            r'(?:youtube\.com/watch\?v=[\w-]{11}'
            r'(?:&[^\s]*)?'
            r'|youtu\.be/[\w-]{11}'
            r'(?:\?[^\s]*)?))'
        )

        match = regex.search(text)
        return match.group(1) if match else None




    def markup_links(self, text):

        URL_REGEX = re.compile(r'(https?://[^\s]+)',re.IGNORECASE)

        def _repl(match):
            url = match.group(1)
            return f"[ref={url}]🔗 {url}[/color][/ref]"
        return URL_REGEX.sub(_repl, text)
    
    def on_ref_press(self, instance, ref):

        webbrowser.open(ref)

    def open_emoji_picker(self, btn):

        self._pending_reaction_target = btn._message_text
        self.emoji_picker.open()

    def _on_emoji_selected(self, emoji):
        self.emoji_picker.dismiss()
        orig = self._pending_reaction_target or ""
        reaction_text = f"{USERNAME} reacted to “{orig}” with {emoji}"
        
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

        new_msg = {
            "sender": USERNAME,
            "recipient": self.active_conversation,
            "message": reaction_text,
            "timestamp": Clock.get_time(),
            "image": None
        }
        messages.append(new_msg)
        with open(message_file, "w") as f:
            json.dump(messages, f, indent=2)

        self.refresh_chat_display(0)

    def refresh_chat_display(self, dt):
        if not self.active_conversation:
            return

        self.chat_list.clear_widgets()
        history = get_message_history(USERNAME, self.active_conversation)
        app = App.get_running_app()
        theme = app.current_theme

        if not history:
            self.chat_list.add_widget(Label(
                text="(no messages yet)",
                size_hint_y=None,
                height=30,
                color=theme['secondary_text']
            ))
        else:
            for entry in history:
                if entry["image"] != True:
                    sender = entry.get("sender", self.active_conversation)
                    msg = entry["message"]
                    linked_msg = self.markup_links(msg)

                    row = BoxLayout(orientation='horizontal', size_hint_y=None, height=30)

                    lbl = Label(
                        text=f"[b]{sender}:[/b] {linked_msg}",
                        markup=True,
                        size_hint_y=None,
                        height=30,
                        halign="left",
                        valign="middle",
                        color=theme['text_color']
                    )
                    lbl.text_size = (self.chat_list.width * 0.9, None)
                    lbl.bind(on_ref_press=self.on_ref_press)
                    self.chat_list.add_widget(lbl)

                    react_btn = Button(
                        text=" + ",
                        size_hint_x=0.1,
                        font_size=14,
                        background_color=theme['button_bg'],
                        color=theme['button_text']
                    )

                    react_btn._message_text = msg
                    react_btn.bind(on_press=self.open_emoji_picker)
                    row.add_widget(react_btn)

                    self.chat_list.add_widget(row)
                    
                    # url = self.get_youtube_url(msg)
                    # if url:
                    #     try:
                    #         print(f"trying to download {url}")
                    #         filename = APP_DIR/f"{time.time()}.mp4"
                    #         YouTube(url).streams.first().download(filename)
                    #         player = VideoPlayer(source=filename, state='play',options={'fit_mode': 'contain'})

                    #         self.chat_list.add_widget(player)
                    #     except Exception as e:
                    #         print(f"Error playing video: {e}")


                elif entry["image"] == True:
                    try:
                        image_bytes = base64.b64decode(entry["message"])
                        image = Image.open(io.BytesIO(image_bytes))

                        temp_image_path = APP_DIR / "temp_images.png"
                        
                        
                        image.save(str(temp_image_path), "PNG")

                        image_container = BoxLayout(
                            orientation='vertical',
                            size_hint_y=None,
                            height=200,
                            spacing=5
                        )

                        sender = entry.get("sender", self.active_conversation)
                        sender_label = Label(
                            text=f"[b]{sender}:[/b]",
                            markup=True,
                            size_hint_y=None,
                            height=20,
                            halign="left",
                            valign="middle",
                            color=theme['text_color']
                        )
                        sender_label.text_size = (self.chat_list.width * 0.9, None)                     


                        image_widget = KivyImage(
                            source=str(temp_image_path),
                            size_hint_y=None,
                            height=150,
                            allow_stretch=True,
                            keep_ratio=True
                        )

                        image_container.add_widget(sender_label)
                        image_container.add_widget(image_widget)
                        

                        self.chat_list.add_widget(image_container)

                    except Exception as e:
                        print(f"Error saving image: {e}")
                        return None

        Clock.schedule_once(lambda dt: self.chat_pane.scroll_to(self.chat_list.children[0]), 0.1)

    def update_conversations(self, dt):
        if not USERNAME:
            return
        self.conv_list.clear_widgets()
        for contact in get_contacts(USERNAME):
            history = get_message_history(USERNAME, contact)
            last = history[-1]["message"] if history else "(no messages)"
            last = "image" if history[-1]["image"] == True else last
            tile = ConversationTile(contact, last)
            tile.bind(on_touch_down=lambda inst, touch, t=tile: self.on_tile_click(t, touch))
            self.conv_list.add_widget(tile)

    def on_tile_click(self, tile, touch):
        if not tile.collide_point(*touch.pos):
            return
        convo_with = tile.children[1].text
        self.active_conversation = convo_with
        self.refresh_chat_display(0)

class ChatWizardApp(App):
    def build(self):
        self.theme_name = 'dark'
        self.current_theme = THEMES[self.theme_name]

        Window.clearcolor = self.current_theme['window_bg']

        Window.size = (800, 600)
        Window.minimum_width, Window.minimum_height = 400, 300

        sm = ScreenManager()
        sm.add_widget(RegisterScreen(name="register"))
        sm.add_widget(MessageScreen(name="messages"))
        return sm

    def apply_theme_to_widget(self, widget):
        theme = self.current_theme

        if isinstance(widget, Label):
            widget.color = theme['text_color']
        elif isinstance(widget, Button):
            widget.background_color = theme['button_bg']
            widget.color = theme['button_text']
        elif isinstance(widget, TextInput):
            widget.background_color = theme['input_bg']
            widget.foreground_color = theme['input_text']

        if hasattr(widget, 'children'):
            for child in widget.children:
                self.apply_theme_to_widget(child)

    def apply_theme(self):
        Window.clearcolor = self.current_theme['window_bg']

        for screen in self.root.children:
            self.apply_theme_to_widget(screen)

if __name__ == '__main__':
    ChatWizardApp().run()
