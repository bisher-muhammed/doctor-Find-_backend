from rest_framework import generics, mixins, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import ChatRoom, ChatMessage
from .serializers import*
import logging
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from Users.permissions import IsPatient

logger = logging.getLogger(__name__)

class ChatRoomListCreateView(generics.ListCreateAPIView):
    serializer_class = ChatRoomSerializer
    permission_classes = [IsPatient]

    def get_queryset(self):
        user = self.request.user
        queryset = ChatRoom.objects.none()  # Default empty queryset

        # Filter chat rooms based on user type
        if user.user_type == 'patient':
            queryset = ChatRoom.objects.filter(patient=user)
        elif user.user_type == 'doctor':
            queryset = ChatRoom.objects.filter(doctor__user=user)

        # Get the search term from the query parameters
        search_term = self.request.query_params.get('search', None)
        
        # If a search term exists, filter chat rooms by doctor's first name
        if search_term:
            queryset = queryset.filter(
                Q(doctor__first_name__icontains=search_term)
            )

        return queryset


    def perform_create(self, serializer):
        serializer.save()

class StartChatView(generics.GenericAPIView):
    serializer_class = ChatRoomSerializer
    permission_classes = [IsPatient]

    def post(self, request, doctor_id=None):
        user = request.user
        logger.info(f"Received request from user: {user.id} to start chat with doctor_id: {doctor_id}")

        existing_room = ChatRoom.objects.filter(
            doctor_id=doctor_id, patient=user
        ).first()
        if existing_room:
            logger.info(f"Returning existing chat room with ID: {existing_room.id}")
            return Response({'room_id': existing_room.id}, status=status.HTTP_200_OK)

        serializer = self.get_serializer(data={
            'doctor': doctor_id,
            'patient': user.id
        })

        if serializer.is_valid():
            chat_room = serializer.save()
            logger.info(f"New chat room created with ID: {chat_room.id}")
            return Response({'room_id': chat_room.id}, status=status.HTTP_201_CREATED)

        logger.error(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
logger = logging.getLogger(__name__)
from rest_framework.parsers import MultiPartParser, FormParser

class ChatMessageListCreateView(generics.ListCreateAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = [IsPatient]
    parser_classes = [MultiPartParser, FormParser]  # To handle file uploads

    def get_queryset(self):
        room_id = self.kwargs.get('room_id')
        return ChatMessage.objects.filter(room__id=room_id)

    def perform_create(self, serializer):
        room_id = self.kwargs.get('room_id')
        user = self.request.user
        room = ChatRoom.objects.get(id=room_id)

        content = self.request.data.get('content', '').strip()
        has_attachments = any([
            self.request.FILES.get('image'),
            self.request.FILES.get('video'),
            self.request.FILES.get('voice_message')
        ])

        # Ensure that either content or an attachment is provided
        if not content and not has_attachments:
            raise ValidationError("Content or at least one attachment is required.")

        serializer.save(sender=user, room=room)






class ChatRoomDetailView(generics.RetrieveAPIView):
    permission_classes = [IsPatient]
    def get(self, request, room_id, format=None):
        try:
            chat_room = ChatRoom.objects.get(id=room_id)
            serializer = ChatRoomSerializer(chat_room)
            return Response(serializer.data)
        except ChatRoom.DoesNotExist:
            return Response({'error': 'Chat room not found'}, status=status.HTTP_404_NOT_FOUND)