import kivy
# kivy.require('1.9.1')

from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput

from kivy.config import Config
Config.set('graphics', 'width',  300)
Config.set('graphics', 'height', 100)
Config.set('graphics', 'resizable', 0)

class PasswordScreen(GridLayout):

    def __init__(self, **kwargs):
        super(PasswordScreen, self).__init__(**kwargs)
        self.cols = 1
        self.add_widget(Label(text='password'))
        self.password = TextInput(password=True, multiline=False)
        self.add_widget(self.password)


class MyApp(App):

    def build(self):
        return PasswordScreen()


if __name__ == '__main__':
    MyApp().run()
