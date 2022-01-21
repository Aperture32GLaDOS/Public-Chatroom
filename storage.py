import sqlite3
import queue
import threading
import encryption
import events


class StorageMethod:  # A superclass for a storage method
    def __init__(self):
        pass

    def getUser(self, ID):  # With a user ID, get their username and password
        return "userName", "userPassword"

    def getGroup(self, ID):  # With a group's ID, get its name
        return "groupName"

    def getGroupsFromUser(self, userID):  # Get a list of groups which a user is in
        return ["groupID1", "groupID2"]

    def getUsersFromGroup(self, groupID):  # Get a list of users which are in a group
        return ["userID1", "userID2"]

    def addUser(self, userName,
                userPass):  # Given a username and hashed password, add the user to the database, and return their ID
        return 1

    def addGroup(self, groupName):  # Given a group's name, add it to the database, and return its ID
        return 1

    def addUserToGroup(self, userID,
                       groupID):  # Given a user and group's ID, add the user to the group, and return the userGroup ID
        return 1

    def removeUserFromGroup(self, userID, groupID):  # Given a user and group's ID, remove the user from the group if
        # they are in it
        pass

    def getConnection(self):
        pass

    def closeConnection(self):
        pass


class SQLDatabase(StorageMethod):
    def __init__(self):  # Initialises a database (if it isn't already initialised)
        self.getConnection()
        SQLCommand = """CREATE TABLE IF NOT EXISTS users (userID INTEGER PRIMARY KEY,
                                                          userName TEXT,
                                                          userPassword TEXT);
                        CREATE TABLE IF NOT EXISTS groups (groupID INTEGER PRIMARY KEY,
                                                           groupName TEXT);
                        CREATE TABLE IF NOT EXISTS userGroups (usergroupID INTEGER PRIMARY KEY,
                                                               userID INTEGER,
                                                               groupID INTEGER);"""  # An SQL command which creates 3 tables; one user table, one group table and one to link them in
        # order to avoid a many-to-many relationship.
        self.databaseCursor.executescript(SQLCommand)
        self.databaseConnection.commit()
        try:
            self.getGroup(1)  # Try and get the default group
        except TypeError:
            self.addGroup("default")  # If it doesn't exist, create it.
        self.closeConnection()

    def getConnection(self):
        self.databaseConnection = sqlite3.Connection("database.db")
        self.databaseCursor = self.databaseConnection.cursor()

    def closeConnection(self):
        self.databaseCursor.close()
        self.databaseConnection.close()

    def addUser(self, userName, userPass):
        SQLCommand = """INSERT INTO users
                        VALUES(NULL, ? ,?)"""  # Here, the null just means that the userID is automatically generated, and the ? means that they are passed via python.
        self.databaseCursor.execute(SQLCommand, (userName, userPass,))
        self.databaseConnection.commit()
        ID = self.databaseCursor.lastrowid
        return ID

    def addGroup(self, groupName):
        SQLCommand = """INSERT INTO groups
                        VALUES(NULL, ?)"""
        self.databaseCursor.execute(SQLCommand, (groupName,))
        self.databaseConnection.commit()
        ID = self.databaseCursor.lastrowid
        return ID

    def addUserToGroup(self, userID, groupID):
        SQLCommand = """INSERT INTO userGroups
                        VALUES(NULL, ?, ?)"""
        self.databaseCursor.execute(SQLCommand, (userID, groupID))
        self.databaseConnection.commit()
        ID = self.databaseCursor.lastrowid
        return ID

    def removeUserFromGroup(self, userID, groupID):
        SQLCommand = """DELETE FROM userGroups WHERE userID=? AND groupID=?"""
        self.databaseCursor.execute(SQLCommand, (userID, groupID, ))
        self.databaseConnection.commit()

    def getUser(self, ID):
        SQLCommand = """SELECT userName, userPassword FROM users WHERE userID=?"""
        self.databaseCursor.execute(SQLCommand, (ID,))
        result = self.databaseCursor.fetchone()  # Since the userID is the primary key, fetchone is used
        return result[0], result[1]

    def getGroup(self, ID):
        SQLCommand = """SELECT groupName FROM groups WHERE groupID=?"""
        self.databaseCursor.execute(SQLCommand, (ID,))
        result = self.databaseCursor.fetchone()[0]
        return result

    def getGroupsFromUser(self, userID):
        SQLCommand = """SELECT groupID FROM userGroups WHERE userID=?"""
        self.databaseCursor.execute(SQLCommand, (userID,))
        results = self.databaseCursor.fetchall()
        formattedResults = []
        for result in results:
            formattedResults.append(result[0])
        return formattedResults

    def getUsersFromGroup(self, groupID):
        SQLCommand = """SELECT userID FROM userGroups WHERE groupID=?"""
        self.databaseCursor.execute(SQLCommand, (groupID,))
        results = self.databaseCursor.fetchall()
        formattedResults = []
        for result in results:
            formattedResults.append(result[0])
        return formattedResults


class MessageStorage:  # Used to store messages from clients
    def __init__(self, events):
        self.messages = {}
        self.toMessages = queue.Queue()
        self.messageCounter = 0
        self.events = events
        try:  # Try to load the messages in
            AESKey = encryption.readAESKey("AES.key")
            messages = encryption.readEncryptedJSON("messages.enc", AESKey)
            self.messages = messages
        except FileNotFoundError:
            pass
        storageThread = threading.Thread(target=self.main, daemon=True)
        storageThread.start()

    def putMessage(self, message):  # To put messages into the dictionary from multiple threads, a queue is used
        self.toMessages.put(message)

    def getMessages(self):
        return self.messages.copy()  # Returns a copy of the messages so multiple threads won't try to change the same
    # Object at the same time

    def main(self):
        while True:
            message = self.toMessages.get()  # Get a message from the queue
            try:
                self.messages[message["group"]].append(message["message"])  # And add it to the dictionary's list
            except KeyError:
                self.messages[message["group"]] = [message["message"]]  # If this list has not been created yet,
                # Create it.
            self.messageCounter += 1
            if self.messageCounter >= 1:
                self.events.put(events.SaveMessage(self.getMessages()))
                self.messageCounter = 0
