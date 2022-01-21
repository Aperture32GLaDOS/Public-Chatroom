import socket
import events
import transport
import encryption
import Crypto.PublicKey.RSA
import Crypto.Random
import threading
import queue
import storage
import json

PORT = 8888
eventQueue = queue.Queue()
clients = []
groupClients = {"1": []}
storageMethod = storage.SQLDatabase()


class Client:
    def __init__(self, clientSock: socket.socket, privKey: Crypto.PublicKey.RSA.RsaKey, messageStorage: storage.MessageStorage, groupClients: dict, storageMethod: storage.StorageMethod):
        global clients
        self.clientSock = clientSock
        self.sessionToken = {"id": "0", "randomBytes": "0", "groupID": "1"}
        self.username = 'Guest'
        self.storageMethod = storageMethod
        self.messageStorage = messageStorage
        self.isAPI = False
        try:
            self.handshake(privKey)
        except (ValueError, TimeoutError):  # If the AES decryption fails, or if the socket times-out
            try:
                clients.remove(self)  # Remove the client from the list
            except ValueError:
                pass
            return None  # And stop the constructor
        mainThread = threading.Thread(target=self.main, args=(groupClients, ))
        mainThread.start()

    def handshake(self, privKey: Crypto.PublicKey.RSA.RsaKey) -> None:  # Performs a handshake with a client
        encryptedKey = transport.receiveData(256, self.clientSock)
        AESKey = encryption.decryptDataRSA(privKey, encryptedKey)  # Gets and decrypts the AES key with RSA
        self.AESKey = AESKey
        isAPI = transport.receiveEncryptedData(1, self.clientSock, self.AESKey)
        if isAPI == b"\x01":
            self.isAPI = True

    def resetToken(self):  # If some authentication goes wrong, this is used to log clients out
        self.sessionToken = {"id": "0", "randomBytes": "0", "groupID": "1"}
        self.username = "Guest"

    def showMessage(self, message):  # Displays a debug message
        if self.isAPI:  # If the client is an API,
            return None  # Do not send the debug message
        else:
            transport.sendDynamicData(message.encode("utf-8"), "didSucceedMessage", "utf-8",
                                      self.clientSock, self.AESKey)

    def main(self, groupClients) -> None:
        global eventQueue
        global clients
        if not self.isAPI:  # If the client is an API, they should not receive messages
            groupClients["1"].append(self)
            eventQueue.put(events.RetrieveMessages([self, self.messageStorage]))
        while True:
            try:
                dataType, encoding, data = transport.receiveDynamicData(self.clientSock,
                                                                        self.AESKey)  # Get data from the client
            except (ValueError, TimeoutError, ConnectionResetError):  # If the client has disconnected,
                try:
                    groupClients[self.sessionToken["groupID"]].remove(self)  # If the client is in groupClients,
                    # remove them
                except ValueError:
                    pass
                clients.remove(self)  # Remove the client from the list of clients
                self.clientSock.close()
                return None
            if dataType == "message":  # If the data is a message
                event = events.Message([groupClients, data, self, encoding])  # Send it to all clients
            elif dataType == "makeAccount":  # If the data is a request for a new account,
                userPassword = json.loads(data.decode(encoding))
                event = events.NewAccount([self.storageMethod, self, userPassword["username"], userPassword["password"]])  # Make the new account
            elif dataType == "login":  # If the data is a request to login,
                userPassword = json.loads(data.decode(encoding))
                event = events.Login([self.storageMethod, self, userPassword["username"], userPassword["password"], clients])  # Try to login
            elif dataType == "logout":  # If the client wishes to logout,
                event = events.Logout([self, groupClients])  # And log them out
            elif dataType == "makeGroup":  # If the client wishes to make a group,
                groupName = json.loads(data.decode(encoding))["groupName"]
                event = events.MakeGroup([self, groupName, self.storageMethod])  # Make the new group
            elif dataType == "addUserToGroup":  # If the client wishes to add a user to a group,
                groupInfo = json.loads(data.decode(encoding))
                event = events.AddUserToGroup([self, groupInfo["userID"], groupInfo["groupID"]])  # Attempt to do so
            elif dataType == "leaveGroup":
                info = json.loads(data.decode(encoding))
                event = events.LeaveGroup([self, json.loads(info["token"]), info["group"], self.storageMethod, groupClients,
                                           eventQueue])
            elif dataType == "switchGroup":  # If the user wishes to switch their group,
                groupInfo = json.loads(data.decode(encoding))  # Try to switch their group
                event = events.GroupSwitch([self, groupInfo["groupToSwitchTo"], groupClients, eventQueue])
            elif dataType == "getGroups":
                token = json.loads(json.loads(data.decode(encoding))["token"])  # Get the session token
                event = events.ListGroups([self, token, self.storageMethod])  # And give the client the groups
            elif dataType == "doHeartbeat":  # If the client wishes to perform a heartbeat,
                event = events.Heartbeat([self, data])  # Then do it
            elif dataType == "getMessages":
                event = events.RetrieveMessages([self, self.messageStorage])
            else:
                event = events.Log(data)  # If the data is not any of the above, just log it
            eventQueue.put(event)


def handleEvents(storageMethod):  # A function to handle the events which come in
    global eventQueue
    storageMethod.getConnection()
    while True:
        if eventQueue.empty():
            continue
        else:  # If there is an event in the event queue,
            event = eventQueue.get()
            try:
                event.handle()  # Handle it
            except Exception as e:
                print(e)  # If there is an error, log it and continue


pubKey = encryption.readRSAKeyFromFile("pubKey.rsa")
privKey = encryption.readRSAKeyFromFile("privKey.rsa")
servSocket = socket.socket()
servSocket.bind(("127.0.0.1", PORT))
servSocket.listen()
handlingThread = threading.Thread(target=handleEvents, daemon=True, args=(storageMethod, ))
handlingThread.start()
messageStorage = storage.MessageStorage(eventQueue)
while True:
    try:
        clients.append(Client(servSocket.accept()[0], privKey, messageStorage, groupClients, storageMethod))
    except socket.timeout:
        continue
