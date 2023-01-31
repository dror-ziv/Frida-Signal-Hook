# Frida-Signal-Hook: Capturing In-Out Messages and Saving to SQL Database

## Stage 1: Discovering Relevant Functions
The first challenge was to find the number of functions and classes that contain the sequence "open" in them using frida-trace.

To discover the PID, name, and identifier of the apk, run the following command:
```frida-ps -Uai```
The output should look like this:
```PID Name Identifier
3460 Signal org.thoughtcrime.securesms```

To find all functions that contain "open," run the following command:
```frida-trace -U -i "open" signal```
The output should look like this:
```Started tracing 382 functions. Press Ctrl+C to stop.```
This indicates that there are 382 functions that contain the word "open."

To trim down the list of functions, the `-x` flag can be used to exclude functions that are called regardless of sending or receiving new messages. The full command should look like this:

```frida-trace -U -i "open" signal -x "openssl_get_fork_id" -x "ubidi_open_66" -x "ubidi_open_android" -x "EVP_AEAD_CTX_open" -x "utext_openUChars_66" -x "utext_openUChars_android" -x "__open_2" -x "fdopen" -x "utext_openConstUnicodeString_66" -x "ures_openDirect_66" -x "ures_openDirect_android" -x "open" -x "opendir" -x "ucnv_open_66" -x "ucnv_open_android"```
This will result in two relevant functions: `sqlite3_blob_open` and `sqlite3_blob_reopen`. These functions are called from `libsqlcipher.so` and are assumed to be called to write to the database every time a new message is received or sent.

To determine the call stack to these functions, use the following JavaScript code:
```Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())```
This will result in a list of call-stacks. After searching through them, the following three functions were found to handle incoming text messages:
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.handleTextMessage`
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.handleMessage`
- `org.thoughtcrime.securesms.messages.MessageContentProcessor.process`

A search in the Signal source code indicated that `handleTextMessage` is the best choice, as it gets a decrypted message and the received time.

For outgoing messages, the `send` method from `sms.MessageSender` was chosen. The only exception is that the `send` method does not get a timestamp with it. However, since it is called when a message is sent (locally), the current time can be obtained using `Date.now`.

## Stage 2
