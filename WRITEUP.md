# Frida-Signal-Hook: Capturing In-Out Messages and Saving to SQL Database
This project is aimed at capturing inbound and outbound messages from the Signal app and saving them to a SQL database.


## Stage 1: Tracing Functions with Frida

The first step was to discover the functions within the Signal app that contain the sequence "open". This was done using the ```frida-trace``` tool. To do this, the process identifier (PID) and name of the Signal app was found by running the following command:

```shell 
frida-ps -Uai
```
The result was:

```shell 
PID  Name                  Identifier
3460  Signal                org.thoughtcrime.securesms
```

Next, the functions containing the word "open" were found using the following command:

```shell 
frida-trace -U -i "open" signal
```
The output should look like this:
```shell 
Started tracing 382 functions. Press Ctrl+C to stop.
```
The result was a long list of functions, with a total of 382 functions containing the word "open".

To narrow down the list of functions, the -x flag was used to remove functions that were called regardless of sending or receiving messages. The final command was:



```shell 
frida-trace -U -i "open" signal -x "openssl_get_fork_id" -x "ubidi_open_66" -x "ubidi_open_android" -x "EVP_AEAD_CTX_open" -x "utext_openUChars_66" -x "utext_openUChars_android" -x "__open_2" -x "fdopen" -x "utext_openConstUnicodeString_66" -x "ures_openDirect_66" -x "ures_openDirect_android" -x "open" -x "opendir" -x "ucnv_open_66" -x "ucnv_open_android"
```

This resulted in two relevant functions:

- `sqlite3_blob_open`
- `sqlite3_blob_reopen`

It was assumed that these functions were called to write to the database every time a new message was received or sent.
after trying to hook to those functions directrly for a while and decyphering from the args they get (js + memory pointers = a bad time)\n
i decided To further investigate, and look in the call stack to these functions - using the following JavaScript code:

```shell 
Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
```

From the call stack, three interesting functions were found:

- `org.thoughtcrime.securesms.messages.MessageContentProcessor.handleTextMessage`
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.handleMessage`
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.process`

After searching the Signal source code, it was found that the `handleTextMessage` function handled incoming text messages and received the decrypted message and received time.


For outgoing messages,the same proccess was repeated and the `send` method from `sms.MessageSender` was chosen. The only exception is that the `send` method does not get a timestamp with it. However, since it is called when a message is sent (locally), the current time can be obtained using `Date.now`.

## Stage 2

After discovering the relevant functions for incoming and outgoing messages, it's time to implement the hook using Frida and JavaScript syntax.
Here's the code snippet for hooking to `handleTextMessage` method of `MessageContentProcessor` class to capture incoming messages:
```javascript
var MessageContentProcessor = Java.use("org.thoughtcrime.securesms.messages.MessageContentProcessor");
     MessageContentProcessor.handleTextMessage.implementation = function(content, message, smsMessageId, groupId, senderRecipient, threadRecipient, receivedTime) {
        //before execution
 	      console.log(message.getBody().get().toString())
	      console.log(receivedTime)
        // Call the original handleTextMessage function
        var result = this.handleTextMessage.apply(this, arguments);

        // after execution

        return result;
        };
```

And here's the code snippet for hooking to `send` method of `MessageSender` class to capture outgoing messages:
```javascript
var MessageSender = Java.use("org.thoughtcrime.securesms.sms.MessageSender");
     MessageSender.send.implementation = function(context, message, threadId, sendType, metricId, insertListener) {
        //before execution
	      console.log(message.getBody())
	      console.log(Date.now())
        // Call the original send function
        var result = this.send.apply(this, arguments);
        // after execution
        return result;
        };
```
With these hooks in place, incoming and outgoing messages will be captured.


## Stage 3: Implementing the Hooks, send and SQL
Now that we have located the relevant functions for incoming and outgoing messages, it is time to implement the hooks using Frida and JavaScript syntax. The hooks will collect the information needed and send it to a Python server for processing.
```javascript
Java.perform(function(){

    // hooking outgoing messages
    var MessageSender = Java.use("org.thoughtcrime.securesms.sms.MessageSender");
     MessageSender.send.implementation = function(context, message, threadId, sendType, metricId, insertListener) {
        //before execution
        const json_message = {};
        var message_str = message.getBody();
        var outgoingFlag = true;
        var timestamp = Date.now();

        json_message.outgoingFlag = outgoingFlag;
        json_message.timestamp = timestamp;
        json_message.message_str = message_str;

        send(json_message)

        // Call the original handleTextMessage function
        var result = this.send.apply(this, arguments);

        // after execution

        return result;
        };

    // hooking incoming messages
    var MessageContentProcessor = Java.use("org.thoughtcrime.securesms.messages.MessageContentProcessor");
     MessageContentProcessor.handleTextMessage.implementation = function(content, message, smsMessageId, groupId, senderRecipient, threadRecipient, receivedTime) {
        //before execution
        const json_message = {};
        var message_str = message.getBody().get().toString();
        var outgoingFlag = false;
        var timestamp = receivedTime;

        json_message.outgoingFlag = outgoingFlag;
        json_message.timestamp = timestamp;
        json_message.message_str = message_str;

        send(json_message)

        // Call the original handleTextMessage function
        var result = this.handleTextMessage.apply(this, arguments);

        // after execution

        return result;
        };


    });
```

Next, we'll set up a SQL database on the server and implement the necessary CRUD operations to handle the incoming data. Since the program is multi-threaded, and we don't expect a high amount of traffic, we can create a new connection to the database every time we need to operate on it.

```python
import frida
import sqlite3

DB_PATH = "messages.db"
JS_PAYLOAD_PATH = "signal_payload.js"



def db_setup():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    listOfTables = cur.execute(
        """SELECT name FROM sqlite_master WHERE type='table'
        AND name='messages'; """).fetchall()
    if not listOfTables:
        conn.execute('''CREATE TABLE messages 
               (id INT AUTO_INCREMENT PRIMARY KEY, 
               outgoingFlag           BOOL    NOT NULL, 
               timestamp            timestamp, 
               message_str        TEXT    NOT NULL);''')

    conn.close()

def add_to_db(outgoingFlag, timestamp, message_str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (outgoingFlag,timestamp,message_str) \
    VALUES (?, ?, ?)", (outgoingFlag, timestamp, message_str));
    conn.commit()
    conn.close()


def on_message(message, data):
    message = message['payload']

    add_to_db(message['outgoingFlag'], message['timestamp'], message['message_str'])
    print(message)




def execute_frida():
    session = frida.get_device_manager().enumerate_devices()[-1].attach("signal")

    with open(JS_PAYLOAD_PATH, 'r') as f:
        script_str = f.read()

    script = session.create_script(script_str)

    script.on("message", on_message)
    script.load()
    input()


def main():
    db_setup()
    execute_frida()


if __name__ == "__main__":
    main()
```
And that's it! You can now run your application and start collecting incoming and outgoing message data. To see the trade-offs, improvements, and known limitations of this project, you can check out the accompanying readme file.

## Conclusion
In this project, we developed a Frida-based tool to capture incoming and outgoing text messages in the Signal app, and save them to a SQL database. By using frida-trace, we discovered the functions related to message storage, and hooked into relevant functions using Frida's JavaScript API. The captured messages were then sent to a Python server for parsing and storing in a SQL database.

This project serves as a proof-of-concept for demonstrating the power of Frida in dynamic analysis of mobile applications. To see the trade-offs, improvements, and known flaws of the project, you are welcome to check the accompanying README file.

