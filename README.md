# Frida-Signal-Hook
Frida-Signal-Hook: Capturing In-Out Messages and Saving to SQL Database.

this project was done as an assignment. For a complete write-up of the development process, please refer to the [WRITE.md file](https://github.com/dror-ziv/Frida-Signal-Hook/blob/main/WRITEUP.md).

## Introduction

Frida-Signal-Hook is a project that captures in-out messages from the Signal app and saves the data to an SQL database, including the timestamp, message type (incoming/outgoing), and message content. Currently, the program only supports text messages.

## build and run
```bash
pip install frida
python server.py
```

## How it works
Frida-Signal-Hook sets up an SQL database and hooks the "send" and "handleTextMessage" functions in the Signal app. It then traces the in-out messages and saves them in the database.

## Tradeoffs and known limitations
- This project was designed as a proof-of-concept and is not built to work on a large scale.
- no contact info is saved (no way to know who did you send/receive a message)
- Every message is saved to the same table, which can lead to data mixing if not properly managed.
- For each message, a new connection to the database is made, which can be inefficient.
- The program may sometimes parse new group messages as gibberish and save them to the database.

## Future improvements
Given more time, the following improvements could be made to Frida-Signal-Hook:

- Add the ability to track the sender/recipient of messages.
- Create a main "conversations" table that references each conversation.
- Save each conversation in a different table, including group messages.
- Support media.
- Improve database connection efficiency.
- Make the communication more "lean" by reducing the size of the JSON file.

## Challenges overcome
- Lack of knowledge or prior experience with Frida.
- Little experience with the Android operating system and Android applications.
