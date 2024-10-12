import socketio



# Initialize the AsyncServer with CORS allowed origins
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=['http://localhost:5173', 'http://127.0.0.1:5173']
)





# Define event handlers directly here
@sio.event
async def connect(sid, environ):
    print('Client connected:', sid)
    

@sio.event
async def disconnect(sid):
    print('Client disconnected:', sid)

@sio.event
async def join_room(sid, data):
    print('the data comming in join room',data)
    room_id = data['room_id']
    await sio.enter_room(sid,room_id)
    print(f"{sid} joined room {room_id}")

@sio.event
async def send_message(sid, data):
    print('form the sendMessage ', data)
    room_id = data.get('room_id')
    content = data.get('content', '')  # Get message or default to empty string   
    image = data.get('image')
    video = data.get('video')
    voice_message = data.get('voice_message')
    
    # Use .get() to avoid KeyError if 'sender_id' is missing
    sender_id = data.get('sender_id')

    if sender_id is None:
        print("Error: 'sender_id' is missing from the data")
        return

    print(f"Message from {sender_id}: {content}")

    # Emit the message to the room
    await sio.emit('receive_message', {
        'content': content,
        'sender_id': sender_id,
        'image': image,
        'video': video,
        'voice_message':voice_message,
    }, room=room_id)

#------------------------------------------------------------------------------------------------------------------------------------------------#
#_call
# Handle audio call event
@sio.event
async def call(sid, data):
    print('Call data received:', data)
    room_id = data['room_id']
    callId = data.get('callId', '')
    sender_id = data['sender_id']
    content = data.get('message', '')

    # Emit the message to the room
    await sio.emit('receive_message', {
        'content': content,
        'callId': callId,
        'sender_id': sender_id,
    }, room=room_id)

# Handle room joining for the call
@sio.event
async def join_call_room(sid, data):
    room_id = data['room_id']
    callId = data['callId']
    await sio.enter_room(sid, room_id)
    print(f"SID {sid} joined room {room_id} for call {callId}")
