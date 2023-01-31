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
