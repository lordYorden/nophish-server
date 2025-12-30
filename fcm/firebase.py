import firebase_admin
from firebase_admin import credentials
from firebase_admin import messaging

def initialize_firebase():      
    cred = credentials.Certificate("serviceKey.json")
    firebase_admin.initialize_app(cred)

def send_fcm_message(topic: str, title: str, body: str, data: dict = None):
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body
        ),
        data=data or {},
        topic=topic,

        # enable analytics labeling
        fcm_options=messaging.FCMOptions(
            analytics_label=topic 
        )
    )

    return messaging.send(message)

if __name__ == "__main__":
    initialize_firebase()
    test_topic = "test_topic"
    response = send_fcm_message(test_topic, "no-phish", "test 1", {"test": "jerbi"})
    print("Successfully sent message:", response)