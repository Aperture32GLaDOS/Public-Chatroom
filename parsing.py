import socket
import encryption
import json
import sys
import transport


def parse(text: str):  # Parses some text as a command
    text = text.strip()  # Removes leading or trailing whitespace
    if text == "":  # If there is no text,
        return Command()  # Simply do nothing
    if text.startswith("\\`"):  # If the text begins with \`,
        return parse("`say " + text[1:])  # Parse the text as a say command with the message beginning with `
    if not text.startswith("`"):  # If the text does not begin with `,
        return parse("`say " + text)  # Parse the text as a say command
    command = text[1:].strip()  # Removes the command prefix from the text
    tokens = command.split(" ")
    if tokens[0] == "connect":
        return Connect(tokens[1], int(tokens[2]))
    elif tokens[0] == "disconnect":
        return Disconnect()
    elif tokens[0] == "help":
        return Help()
    elif tokens[0] == "say":
        return Say(tokens[1:])
    elif tokens[0] == "config":
        return Config(command)
    elif tokens[0] == "stop":
        return Stop()
    elif tokens[0] == "makeAccount":
        return MakeAccount(tokens[1:])
    elif tokens[0] == "login":
        return Login(tokens[1:])
    elif tokens[0] == "logout":
        return Logout()
    elif tokens[0] == "makeGroup":
        return MakeGroup(tokens[1])
    elif tokens[0] == "addUserToGroup":
        return AddUser(tokens[1], tokens[2])
    elif tokens[0] == "switchGroup":
        return SwitchGroup(tokens[1])
    elif tokens[0] == "leaveGroup":
        return LeaveGroup(tokens[1])
    elif tokens[0] == "getGroups":
        return ListGroups()
    else:  # If the command name doesn't exist,
        return Error(tokens[0])  # Display an error message


def setConfig(config, keys,
              newValue):  # Given a dictionary, an array of keys and a value, change what the value of the nested
    # keys are. Equivalent to something like config[key1][key2][key3]... = newVal
    if len(keys) > 1:
        try:
            config[keys[0]] = setConfig(config[keys[0]], keys[1:], newValue)
        except KeyError:  # If part of the key isn't assigned,
            config[keys[0]] = {}  # Assign it a blank dictionary
            setConfig(config[keys[0]], keys[1:], newValue)  # And continue
        return config
    else:
        config[keys[0]] = newValue
        return config


class Command:  # Superclass for any command
    def __init__(self):
        pass

    def handle(self, client):  # Gets the client object, and does something with it
        pass


class Connect(Command):
    def __init__(self, IP, port):
        self.IP = IP
        self.port = port
        configFile = open("config.json", "r")
        config = json.load(configFile)
        configFile.close()
        pubKey = config["servers"][IP]
        self.publicKey = encryption.readRSAKeyFromText(pubKey)

    def handle(self, client):
        client.servSocket.connect((self.IP, self.port))
        client.handshake(self.publicKey)


class Disconnect(Command):
    def handle(self, client):
        client.servSocket.shutdown(0)  # Disconnect from the server
        client.servSocket = socket.socket()  # Create a new socket
        client.readyToReceive = False  # Tell the client that the connection has been removed
        client.AESKey = None  # Delete the AES key used for connection with the now disconnected server


class Help(Command):
    def handle(self, client):
        documentationFile = open("documentation.json", "r")
        documentation = json.load(documentationFile)
        documentationFile.close()
        documentationText = ""
        for command in documentation.keys():
            documentationText += command + ": " + documentation[command] + "\n"
        documentationText = documentationText[:-1]  # Removes the trailing newline
        client.toGUI.put("\n" + documentationText)


class Say(Command):
    def __init__(self, words):
        self.message = " ".join(words)

    def handle(self, client):
        messageAndToken = {"message": self.message, "sessionToken": json.dumps(client.sessionToken)}
        toBeSent = json.dumps(messageAndToken)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "message", "utf-8", client.servSocket, client.AESKey)


class MakeAccount(Command):
    def __init__(self, words):
        self.username = words[0]
        self.password = words[1]

    def handle(self, client):
        userPasswordComb = {"username": self.username, "password": self.password}
        toBeSent = json.dumps(userPasswordComb)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "makeAccount", "utf-8", client.servSocket,
                                  client.AESKey)  # Sends the user/password combination to the server and tells it
        # that the intent is to create a new account


class Login(Command):
    def __init__(self, words):
        self.username = words[0]
        self.password = words[1]

    def handle(self, client):
        userPasswordComb = {"username": self.username, "password": self.password}
        toBeSent = json.dumps(userPasswordComb)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "login", "utf-8", client.servSocket,
                                  client.AESKey)  # Same as with MakeAccount, but sets the intent to login


class Logout(Command):
    def handle(self, client):
        clientData = {"sessionToken": json.dumps(client.sessionToken)}  # Tell the server which client wants to log-out
        toBeSent = json.dumps(clientData)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "logout", "utf-8", client.servSocket, client.AESKey)
        client.resetToken()


class MakeGroup(Command):
    def __init__(self, name):
        self.name = name

    def handle(self, client):
        groupData = {"groupName": self.name}  # Packages the necessary information into one object
        toBeSent = json.dumps(groupData)  # Stringifies said object
        transport.sendDynamicData(toBeSent.encode("utf-8"), "makeGroup", "utf-8", client.servSocket, client.AESKey)
        # And sends it to the server


class SwitchGroup(Command):
    def __init__(self, groupID):
        self.groupID = groupID

    def handle(self, client):
        groupData = {"groupToSwitchTo": self.groupID}
        toBeSent = json.dumps(groupData)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "switchGroup", "utf-8", client.servSocket, client.AESKey)


class ListGroups(Command):
    def handle(self, client):
        relevantData = {"token": json.dumps(client.sessionToken)}
        toBeSent = json.dumps(relevantData)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "getGroups", "utf-8", client.servSocket, client.AESKey)


class LeaveGroup(Command):
    def __init__(self, groupID):
        self.groupID = groupID

    def handle(self, client):
        relevantData = {"token": json.dumps(client.sessionToken),
                        "group": self.groupID}
        toBeSent = json.dumps(relevantData)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "leaveGroup", "utf-8", client.servSocket, client.AESKey)


class AddUser(Command):  # A command to add a user to a group
    def __init__(self, userID, groupID):
        self.userID = userID
        self.groupID = groupID

    def handle(self, client):
        groupData = {"groupID": self.groupID, "userID": self.userID}  # Packages the group's and user's ID together
        toBeSent = json.dumps(groupData)
        transport.sendDynamicData(toBeSent.encode("utf-8"), "addUserToGroup", "utf-8", client.servSocket, client.AESKey)


class Config(Command):
    def __init__(self, command: str):
        tokens = command.split(" ")
        tokens.pop(0)
        self.type = tokens[0]  # Whether the config is getting or setting
        if self.type == "get":
            self.index = tokens[1:]
        elif self.type == "set":
            self.newVal = command.split("\"")[1]
            keys = command.replace("\"" + self.newVal + "\"", "")  # Removes the new value from the command
            keyTokens = keys.strip().split(" ")[2:]  # Remove the first two (the first being config, the second being
            # the type)
            self.index = keyTokens

    def handle(self, client):
        configFile = open("config.json", "r")
        config = json.load(configFile)
        configFile.close()
        if self.type == "get":
            value = config[self.index[0]]
            for i in self.index[1:]:
                value = value[i]
            client.toGUI.put("\nValue: " + str(value))
        elif self.type == "set":
            config = setConfig(config, self.index, self.newVal)
            configFile = open("config.json", "w")
            json.dump(config, configFile, indent=4)
            configFile.close()


class Stop(Command):
    def handle(self, client):
        sys.exit()


class Error(Command):
    def __init__(self, commandName):
        documentationFile = open("documentation.json", "r")
        documentation = json.load(documentationFile)
        documentationFile.close()
        try:
            self.errorMessage = "\nError: Incorrect syntax for command.\n" + commandName + ": " + documentation[
                commandName]
            # Try to find the error message for the command
        except KeyError:  # If it cannot be found, the command does not exist, so tell this to the user.
            self.errorMessage = "\nError: command " + commandName + " not found. Refer to `help for more info"

    def handle(self, client):
        client.toGUI.put(self.errorMessage)
