# Frida-Signal-Hook
Frida-Signal-Hook: Capturing In-Out Messages and Saving to SQL Database.

this project was done as an assignment. For a complete write-up of the development process, please refer to the [WRITEUP.md file](https://github.com/dror-ziv/Frida-Signal-Hook/blob/main/WRITEUP.md).

## Introduction

Frida-Signal-Hook is a powerful tool for capturing in-out messages from the Signal app and saving the data to an SQL database. This project provides valuable insights into messaging patterns by capturing the timestamp, message type (incoming/outgoing), and message content. Currently, the program only supports text messages, but support for media is planned for future releases.


## build and run
```bash
pip install frida
python server.py
```

## How it works
Frida-Signal-Hook sets up an SQL database and hooks into the "send" and "handleTextMessage" functions in the Signal app. The program then traces the in-out messages and saves them to the database for future analysis.


## Limitations and Considerations
- This project was designed as a proof-of-concept and may not be suitable for large-scale usage
- no contact info is saved (no way to know who did you send/receive a message)
- Every message is saved to the same table, which can lead to data mixing if not properly managed.
- A new database connection is made for each message, which may not be efficient for large-scale usage.
- The program may sometimes parse new group messages as gibberish and save them to the database.

## Future improvements
Given more time, the following improvements could be made to Frida-Signal-Hook:

- Add the ability to track the sender/recipient of messages.
- Create a main "conversations" table that references each conversation.
- Save each conversation in a different table, including group messages.
- Support media.
- Improve database connection efficiency.
- Reduce the size of the JSON file for more efficient communication.


## Challenges overcome
- Lack of knowledge or prior experience with Frida.
- Little experience with the Android operating system and Android applications.
