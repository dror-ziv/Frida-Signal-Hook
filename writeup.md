# Frida-Signal-Hook: Capturing In-Out Messages and Saving to SQL Database
This project is aimed at capturing inbound and outbound messages from the Signal app and saving them to a SQL database.


##Stage 1: Tracing Functions with Frida

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
-`sqlite3_blob_open`
-`sqlite3_blob_reopen`

It was assumed that these functions were called to write to the database every time a new message was received or sent.
after trying to hook to those functions directrly for a while and decyphering from the args they get (js + memory pointers = a bad time)
i decided To further investigate, and look in the call stack to these functions was found using the following JavaScript code:


```shell 
Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
```

From the call stack, three interesting functions were found:

- `org.thoughtcrime.securesms.messages.MessageContentProcessor.handleTextMessage`
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.handleMessage`
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.process`

After searching the Signal source code, it was found that the `handleTextMessage` function handled incoming text messages and received the decrypted message and received time.


For outgoing messages, the `send` method from `sms.MessageSender` was chosen. The only exception is that the `send` method does not get a timestamp with it. However, since it is called when a message is sent (locally), the current time can be obtained using `Date.now`.

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
With these hooks in place, incoming and outgoing messages will be captured, formatted as JSON, and sent to the Python server for further processing.





