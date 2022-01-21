import gui
import socket
import transport
import encryption
import parsing
import Crypto.PublicKey.RSA
import Crypto.Random
import queue
import threading
import time
import json


class Client:  # A class for the client, which is used to pass information down the callstack
    def __init__(self):
        self.readyToReceive = False
        self.sessionToken = {"id": "0", "randomBytes": "0", "groupID": "1"}
        self.fromGUI = queue.Queue()
        self.toGUI = queue.Queue()
        self.clearGUI = queue.Queue()
        self.eventQueue = queue.Queue()
        self.servSocket = socket.socket()
        gui.startGUI(self.fromGUI, self.toGUI, self.clearGUI)
        self.AESKey = None
        self.messageReceiver = threading.Thread(target=self.getServerMessages, daemon=True)
        self.messageReceiver.start()
        self.executeGUICommands()

    def handshake(self, publicKey: Crypto.PublicKey.RSA):  # Performs a handshake with a server, creating a shared key
        self.AESKey = encryption.generateKey()
        AESEncrypted = encryption.encryptDataRSA(publicKey, self.AESKey)
        transport.sendData(AESEncrypted, self.servSocket)
        transport.sendEncryptedData(b"\x00", self.servSocket, self.AESKey)  # Tells the server that the client isn't an
        # API
        self.readyToReceive = True
        self.toGUI.put("\nSuccessful connection to server!")

    def resetToken(self):
        self.sessionToken = {"id": "0", "randomBytes": "0", "groupID": "1"}

    def executeGUICommands(self):
        while True:
            unParsedCommand = self.fromGUI.get()
            try:
                parsedCommand = parsing.parse(unParsedCommand)
                parsedCommand.handle(self)
            except Exception as e:  # Very bare exception clause, so I will also print the exception to console
                print(e)
                commandWord = unParsedCommand.strip().split(" ")[0]  # Strips whitespace and gets the first word
                errorCommand = parsing.Error(commandWord[1:])
                errorCommand.handle(self)  # This does assume that it's always the user's fault, so be sure to check
                # the console if unexpected behaviour occurs

    def getServerMessages(self):
        while True:
            if not self.readyToReceive:  # If the socket is not connected,
                time.sleep(0.5)  # Wait a while (so this doesn't lag out the whole client)
                continue  # And check again
            try:
                dataType, encoding, data = transport.receiveDynamicData(self.servSocket,
                                                                        self.AESKey)  # Get data from the server,
            except ValueError as e:  # If something has gone wrong with receiving the data,
                if not self.readyToReceive:  # Check if the socket is disconnected
                    continue  # And if it is, ignore the exception
                else:  # If the socket is not disconnected,
                    self.toGUI.put("\nAn error has occurred. Please try to re-connect.")  # Show an error to the GUI
                    self.readyToReceive = False
                    self.servSocket.shutdown(0)  # Disconnect from the server
                    self.servSocket = socket.socket()  # Create a new socket
                    continue
            if dataType == "message":  # If the data is a message,
                message = data.decode(encoding=encoding)
                self.toGUI.put("\n" + message)  # Put it in the GUI
            elif dataType == "retrievedMessages":
                messages = json.loads(data.decode(encoding=encoding))  # Load the messages
                self.toGUI.put("\n"+"\n".join(messages))  # Put all the messages in the GUI
            elif dataType == "newToken":  # Used for logging in
                tokenInfo = json.loads(data.decode(encoding))
                newToken = json.loads(tokenInfo["newToken"])
                if newToken == "":
                    self.toGUI.put("\nLogin/account creation failed")
                else:
                    self.sessionToken = newToken
                    if newToken["id"] == "0":
                        self.toGUI.put("\nLogin/account creation failed")
                    else:
                        self.toGUI.put("\nLogin/account creation successful! Your user ID is " + str(newToken["id"]))
            elif dataType == "changeToken":  # Used whenever the server wishes to change the client's token
                token = json.loads(data.decode(encoding))
                if token["groupID"] != self.sessionToken["groupID"]:  # If the group has been switched,
                    self.clearGUI.put(1)  # Clear the screen
                    while not self.clearGUI.empty():
                        time.sleep(0.5)  # Wait for the GUI to be cleared
                    self.toGUI.put(f"Group switched to {token['groupID']}")  # And put a message in
                self.sessionToken = token
            elif dataType == "groupID":
                groupID = json.loads(data.decode(encoding))["groupID"]
                self.toGUI.put("\nSuccess in creating new group! The ID is " + str(groupID))
            elif dataType == "listOfGroups":
                groupsList = json.loads(data.decode(encoding))
                self.toGUI.put("\nYou are in the following groups:\n" + "\n".join(groupsList))
            elif dataType == "didSucceedMessage":
                self.toGUI.put(data.decode(encoding))
            else:
                continue  # If the data is none of the above, ignore it.


client = Client()
