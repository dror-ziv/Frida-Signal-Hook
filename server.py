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