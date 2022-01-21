import transport
import encryption
import socket
import json


def getConnection(IP: str, port: int, publicKey) -> (bytes, socket.socket):  # Given the IP, port and public key of a
    # server, get an AES key for encryption and a socket with which to communicate with
    servSocket = socket.socket()
    servSocket.connect((IP, port))
    AESKey = encryption.generateKey()
    AESEncrypted = encryption.encryptDataRSA(publicKey, AESKey)
    transport.sendData(AESEncrypted, servSocket)
    transport.sendEncryptedData(b"\x01", servSocket, AESKey)
    return AESKey, servSocket


def sendMessage(servSocket: socket.socket, AESKey: bytes, message: str,
                sessionToken: dict = None):  # Given a socket, AESKey, message and (optionally) a session token, send a
    # message
    if sessionToken is None:
        sessionToken = {"id": "0", "randomBytes": "0", "groupID": "1"}  # If the session token is not given,
        # Set it to be default
    messageAndToken = {"message": message,
                       "sessionToken": json.dumps(sessionToken)}
    toSend = json.dumps(messageAndToken)
    transport.sendDynamicData(toSend.encode("utf-8"), "message", "utf-8", servSocket, AESKey)


def getMessages(servSocket: socket.socket, AESKey: bytes, sessionToken: dict) -> list:  # Gets a list of messages
    toSend = json.dumps(sessionToken)
    transport.sendDynamicData(toSend.encode("utf-8"), "getMessages", "utf-8", servSocket, AESKey)
    dataType, encoding, data = transport.receiveDynamicData(servSocket, AESKey)
    return json.loads(data.decode(encoding))


def login(servSocket: socket.socket, AESKey: bytes, username: str, password: str) -> dict:  # Logs in, and gives a
    # session token
    # Be aware, the username must include the user ID, in the format username:ID
    usernamePassword = {"username": username,
                        "password": password}
    toSend = json.dumps(usernamePassword)
    transport.sendDynamicData(toSend.encode("utf-8"), "login", "utf-8", servSocket, AESKey)
    dataType, encoding, data = transport.receiveDynamicData(servSocket, AESKey)
    newToken = json.loads(data.decode("utf-8"))
    return json.loads(newToken["newToken"])


def makeGroup(servSocket: socket.socket, AESKey: bytes, groupName: str) -> int:  # Creates a group and gives the ID of
    # said group
    groupData = {"groupName": groupName}  # Packages the necessary information into one object
    toSend = json.dumps(groupData)
    transport.sendDynamicData(toSend.encode("utf-8"), "makeGroup", "utf-8", servSocket, AESKey)
    dataType, encoding, data = transport.receiveDynamicData(servSocket, AESKey)
    groupInfo = json.loads(data.decode(encoding))
    return int(groupInfo["groupID"])


def switchToGroup(servSocket: socket.socket, AESKey: bytes, groupID: int) -> dict:  # Switch to a group, so that when
    # A message is sent, it is sent to that group
    groupData = {"groupToSwitchTo": groupID}
    toSend = json.dumps(groupData)
    transport.sendDynamicData(toSend.encode("utf-8"), "switchGroup", "utf-8", servSocket, AESKey)
    dataType, encoding, data = transport.receiveDynamicData(servSocket, AESKey)
    newToken = json.loads(data.decode(encoding))
    return newToken


def addUserToGroup(servSocket: socket.socket, AESKey: bytes, groupID: int, userID: int):
    groupData = {"groupID": groupID, "userID": userID}  # Packages the group's and user's ID together
    toSend = json.dumps(groupData)
    transport.sendDynamicData(toSend.encode("utf-8"), "addUserToGroup", "utf-8", servSocket, AESKey)


def leaveGroup(servSocket: socket.socket, AESKey: bytes, groupID: int, sessionToken: dict):
    relevantData = {"token": json.dumps(sessionToken),
                    "group": groupID}
    toBeSent = json.dumps(relevantData)
    transport.sendDynamicData(toBeSent.encode("utf-8"), "leaveGroup", "utf-8", servSocket, AESKey)


def listGroups(servSocket: socket.socket, AESKey: bytes, sessionToken: dict) -> list:  # Gives a list of groups which
    # The API is in
    relevantData = {"token": json.dumps(sessionToken)}
    toSend = json.dumps(relevantData)
    transport.sendDynamicData(toSend.encode("utf-8"), "getGroups", "utf-8", servSocket, AESKey)
    dataType, encoding, data = transport.receiveDynamicData(servSocket, AESKey)
    return json.loads(data.decode(encoding))


def makeAccount(servSocket: socket.socket, AESKey: bytes, username: str, password: str) -> dict:  # Makes an account,
    # and gives a session token
    usernamePassword = {"username": username,
                        "password": password}
    toSend = json.dumps(usernamePassword)
    transport.sendDynamicData(toSend.encode("utf-8"), "makeAccount", "utf-8", servSocket, AESKey)
    dataType, encoding, data = transport.receiveDynamicData(servSocket, AESKey)
    newToken = json.loads(data.decode("utf-8"))
    return json.loads(newToken["newToken"])


def heartBeat(servSocket: socket.socket, AESKey: bytes):  # Performs a heartbeat so the program doesn't stop before the
    # server can handle API calls
    toSend = encryption.generateKey()
    transport.sendDynamicData(toSend, "doHeartbeat", "none", servSocket,
                              AESKey)  # Tell the server to perform a heartbeat
    transport.receiveDynamicData(servSocket, AESKey)
