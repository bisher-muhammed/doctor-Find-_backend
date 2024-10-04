from django.urls import path
from .views import *

urlpatterns = [
    path('chatrooms/', ChatRoomListCreateView.as_view(), name='chatroom-list-create'),
    path('start_chat/<int:doctor_id>/', StartChatView.as_view(), name='start_chat'),
    path('chat_rooms/<int:room_id>/', ChatMessageListCreateView.as_view(), name='chatmessage-list-create'),
    path('chatrooms/<int:room_id>/', ChatRoomDetailView.as_view(), name='chatroom-detail'),
]
