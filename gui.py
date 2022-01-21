import tkinter
import threading
import time


def readOnly(event):  # Function used to make certain widgets read-only
    if event.state == 12 and event.keysym == "c":  # Event state 12 is copying or pasting, so I also make sure that
        # the user is pressing c, so they can't paste into the widget
        return
    else:
        return "break"


def startGUI(fromGUI, toGUI, clearGUI):
    guiStarter = threading.Thread(target=GUI, args=(fromGUI, toGUI, clearGUI, ), daemon=True)
    guiStarter.start()


class GUI:
    def __init__(self, fromGUI, toGUI, clearGUI):
        self.fromGUI = fromGUI
        self.toGUI = toGUI
        self.clearGUI = clearGUI
        self.window = tkinter.Tk()
        self.window.protocol("WM_DELETE_WINDOW", self.onExit)
        self.text = tkinter.Text()
        self.text.pack()
        self.text.bind("<Key>", lambda e: readOnly(e))  # Makes any key press be ignored
        self.entryBar = tkinter.Text(height=1)
        self.entryBar.pack()
        self.entryBar.configure()
        self.entryBar.bind("<Return>", lambda e: self.getEnteredText(
            e))  # Whenever the entry bar is pressed, move the text to the fromGUI queue
        windowUpdater = threading.Thread(target=self.updateWindow)
        windowUpdater.start()
        self.window.mainloop()

    def updateWindow(self):  # Inserts text from the back-end into the GUI
        self.text.insert(tkinter.END, "Welcome to the open-source chatroom!")
        while True:
            if not self.clearGUI.empty():
                self.text.delete("1.0", tkinter.END)
                while not self.clearGUI.empty():
                    self.clearGUI.get()
            if not self.toGUI.empty():
                self.text.insert(tkinter.END, self.toGUI.get())
            time.sleep(0.1)

    def getEnteredText(self, event):  # Gets text from the GUI and feeds it into the back-end
        self.fromGUI.put(self.entryBar.get("1.0", tkinter.END))
        self.entryBar.delete("1.0", tkinter.END)

    def onExit(self):
        self.fromGUI.put("`stop")  # Tells the backend to stop execution
