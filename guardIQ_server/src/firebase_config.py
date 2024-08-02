import json
import pyrebase
import getpass 

def getFirebaseAPP():
    config={
        "apiKey": "AIzaSyDDZNpHxBx-JJQEzxIPHSXaMcq4aASN6yM",
        "authDomain": "aetherwatch-fde03.firebaseapp.com",
        "databaseURL": "https://aetherwatch-fde03-default-rtdb.firebaseio.com",
        "projectId": "aetherwatch-fde03",
        "storageBucket": "aetherwatch-fde03.appspot.com",
        "messagingSenderId": "674693600514",
        "appId": "1:674693600514:web:202921b1247caa3ddd9e1b",
        "measurementId": "G-5YWXSBZKXD"
    }
    firebase = pyrebase.initialize_app(config)
    db = firebase.database()
    authe = firebase.auth()
    return authe, db

def authenticate_user(auth) :
    email = input('Enter email id : ')
    password = getpass.getpass('Enter password : ')

    try:
        user = auth.sign_in_with_email_and_password(email, password)
        # uid = user['localId'] 
        # print(uid) # Get the UID of the authenticated user
        print("Authentication successful\n\n")
        return user
    except Exception as e:
        error_data = json.loads(e.args[1])
        print("Authentication failed:", error_data['error']['message'], "\n\n")
        return 0 

def getNextRequestNo(database, user):
    try:
        requests = database.child('bharatdns').child('requests').get(user['idToken']).val()
        if requests is None:
            return 0  # Or any appropriate handling for no data case
        return len(requests)
    except Exception as e:
        print(f"Error retrieving requests: {e}")
        return 0  # Handle exception gracefully

def create_data_object(query_name , client_address , resolved, time , malicious , blacklist , whitelist , elapsed_time): 
    data = {
        'query_name': str(query_name),
        'client_address': client_address,
        'resolved_ip': str(resolved),
        'time': str(time),
        'time_elapsed': str(elapsed_time),
        'whitelist': int(whitelist),
        'blacklist': int(blacklist),
        'malicious': float(malicious)
    }
    return data
    
def input_data(database, user, msg):
    data = {str(getNextRequestNo(database, user)) : msg}
    requests_ref = database.child("bharatdns").child("requests")
    requests_ref.update(data , user['idToken'])
