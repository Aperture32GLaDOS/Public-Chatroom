import socket
import encryption
import json


def receiveData(numOfBytes: int,
                socketToReceiveFrom: socket.socket) -> bytes:  # Receives a certain number of bytes from a socket
    return socketToReceiveFrom.recv(numOfBytes)


def sendData(data: bytes, socketToSendTo: socket.socket) -> None:  # Sends raw data to a socket
    socketToSendTo.send(data)


def sendEncryptedData(dataToSend: bytes, socketToSendTo: socket.socket,
                      AESKey: bytes) -> None:  # Sends encrypted data to a socket:
    nonce, ciphertext, tag = encryption.encryptDataAES(dataToSend, AESKey)
    totalEncryptedData = nonce + ciphertext + tag
    socketToSendTo.send(totalEncryptedData)


def receiveEncryptedData(lengthOfData: int, socketToReceiveFrom: socket.socket,
                         AESKey: bytes) -> bytes:  # Receives encrypted data from a socket
    nonce = socketToReceiveFrom.recv(16)
    ciphertext = socketToReceiveFrom.recv(lengthOfData)
    tag = socketToReceiveFrom.recv(16)
    plaintext = encryption.decryptDataAES(AESKey, ciphertext, nonce, tag)
    return plaintext


def generateHeader(data: bytes, typeOfData: str,
                   encoding: str) -> bytes:  # Generates a header for a certain type of data, with a certain encoding
    header = {"type": typeOfData, "encoding": encoding, "length": len(data)}
    rawHeader = bytes(json.dumps(header), 'ascii')
    return rawHeader


def headerToChunks(header: bytes) -> list:  # Turns one header into a list of chunks (of size 64 bytes)
    padding = 64 - ((len(header) + 64) % 64)  # This gives the required amount of padding for the last chunk
    chunks = []
    amountOfChunks = len(header) // 64
    i = 0
    for i in range(amountOfChunks):  # For every chunk except the last one,
        chunks.append(header[i * 64:(i + 1) * 64])  # Append the necessary section of the header to the chunks list
    chunks.append(header[(amountOfChunks * 64):])  # Then, add the last bit of the header
    chunks[-1] = chunks[-1] + b"\x00" * padding  # And the padding
    return chunks


def receiveHeader(socketToReceiveFrom: socket.socket, AESKey: bytes) -> dict:  # Receives a header from a socket
    headerChunks = [b"a"]
    while 0 != headerChunks[-1][-1]:  # While the padding has not been detected,
        headerChunks.append(receiveEncryptedData(64, socketToReceiveFrom, AESKey))  # Receive the header from the socket
    headerChunks = headerChunks[1:]
    rawHeader = b""
    for chunk in headerChunks:
        rawHeader += chunk  # Add all the chunks
    for index in range(len(rawHeader)):
        if rawHeader[index] == 0:
            break
    rawHeader = rawHeader[:index]  # Ignore anything before the padding
    decodedHeader = rawHeader.decode("ascii")
    return json.loads(decodedHeader)


def sendHeader(socketToSendTo: socket.socket, header: bytes, AESKey: bytes) -> None:  # Sends a header to a socket
    headerChunks = headerToChunks(header)
    for chunk in headerChunks:
        sendEncryptedData(chunk, socketToSendTo, AESKey)


def sendDynamicData(data: bytes, typeOfData: str, encoding: str, socketToSendTo: socket.socket,
                    AESKey: bytes) -> None:  # Sends data of dynamic size to a socket
    header = generateHeader(data, typeOfData, encoding)  # Generate and send the header
    sendHeader(socketToSendTo, header, AESKey)
    sendEncryptedData(data, socketToSendTo, AESKey)  # Then send the actual data


def receiveDynamicData(socketToReceiveFrom: socket.socket, AESKey: bytes) -> (str, str, bytes):  # Receives data of
    # dynamic size from a socket
    header = receiveHeader(socketToReceiveFrom, AESKey)  # Firstly, receive the header
    sizeOfData = header["length"]  # To know the length of data
    data = receiveEncryptedData(sizeOfData, socketToReceiveFrom, AESKey)  # Then, receive the actual data
    return header["type"], header["encoding"], data
