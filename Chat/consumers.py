# import json
# from channels.generic.websocket import AsyncWebsocketConsumer
# from channels.db import database_sync_to_async
# from datetime import datetime
# from .models import ChatRoom, ChatMessage
# from Users.models import MyUser


# class ChatConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         self.room_id = self.scope['url_route']['kwargs']['room_id']
#         self.room_group_name = f'chat_{self.room_id}'

#         # Fetch room and ensure it exists
#         self.room = await self.get_room(self.room_id)

#         if self.room:
#             # Join the room group
#             await self.channel_layer.group_add(
#                 self.room_group_name,
#                 self.channel_name
#             )
#             await self.accept()

#     async def disconnect(self, close_code):
#         # Leave the room group
#         await self.channel_layer.group_discard(
#             self.room_group_name,
#             self.channel_name
#         )

#     async def receive(self, text_data):
#         text_data_json = json.loads(text_data)
#         message = text_data_json.get('message', '')
#         image = text_data_json.get('image', None)
#         video = text_data_json.get('video', None)
#         voice_message = text_data_json.get('voice_message', None)

#         # Save the message to the database
#         chat_message = await self.save_message(
#             sender_id=self.scope['user'].id,
#             room=self.room,
#             content=message,
#             image=image,
#             video=video,
#             voice_message=voice_message
#         )

#         # Broadcast the message to the room group
#         current_time = datetime.now().strftime("%H:%M")
#         await self.channel_layer.group_send(
#             self.room_group_name,
#             {
#                 'type': 'chat_message',
#                 'message': chat_message.content,
#                 'sender': self.scope['user'].username,
#                 'timestamp': current_time,
#                 'image': chat_message.image.url if chat_message.image else None,
#                 'video': chat_message.video.url if chat_message.video else None,
#                 'voice_message': chat_message.voice_message.url if chat_message.voice_message else None
#             }
#         )

#     async def chat_message(self, event):
#         # Send the message to WebSocket
#         await self.send(text_data=json.dumps({
#             'message': event['message'],
#             'sender': event['sender'],
#             'timestamp': event['timestamp'],
#             'image': event.get('image'),
#             'video': event.get('video'),
#             'voice_message': event.get('voice_message')
#         }))

#     @database_sync_to_async
#     def get_room(self, room_id):
#         try:
#             return ChatRoom.objects.get(id=room_id)
#         except ChatRoom.DoesNotExist:
#             return None

#     @database_sync_to_async
#     def save_message(self, sender_id, room, content, image, video, voice_message):
#         sender = MyUser.objects.get(id=sender_id)
#         return ChatMessage.objects.create(
#             sender=sender,
#             room=room,
#             content=content,
#             image=image,
#             video=video,
#             voice_message=voice_message
#         )
