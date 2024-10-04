from rest_framework import serializers
from Users.models import MyUser
from .models import ChatMessage, ChatRoom
from Doctors.models import DoctorProfile
from Users.models import UserProfile


class ChatRoomSerializer(serializers.ModelSerializer):
    patient_username = serializers.CharField(source='patient.username', read_only=True)
    # patient_profile = serializers.SerializerMethodField()

    patient = serializers.PrimaryKeyRelatedField(queryset=MyUser.objects.filter(user_type='patient'))
    doctor_first_name = serializers.SerializerMethodField()
    doctor_profile = serializers.SerializerMethodField()  
    patient_profile = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ['id', 'patient', 'doctor', 'doctor_first_name', 'doctor_profile', 'created_at','patient_username','patient_profile']

    def get_doctor_first_name(self, obj):
        return obj.doctor.first_name

    def get_doctor_profile(self, obj):
        # Assuming 'doctor' is a ForeignKey to a `DoctorProfile` model
        if obj.doctor and obj.doctor.profile_pic:
            return obj.doctor.profile_pic.url  # Return URL to the doctor's profile picture
        return None
    
    def get_patient_profile(self, obj):
    # Assuming 'patient' is a ForeignKey to MyUser
        if obj.patient and obj.patient.User_profile.exists():
            profile = obj.patient.User_profile.first()  # Get the first UserProfile related to the patient
            if profile.profile_pic:
                return profile.profile_pic.url  # Return URL to the user's profile picture
        return None

    


    def validate(self, attrs):
        patient = attrs.get('patient')
        doctor = attrs.get('doctor')

        # Ensure only one chat room exists between the same patient and doctor
        if ChatRoom.objects.filter(patient=patient, doctor=doctor).exists():
            raise serializers.ValidationError("A chat room with these participants already exists.")
        return attrs



class ChatMessageSerializer(serializers.ModelSerializer):
    sender = serializers.PrimaryKeyRelatedField(read_only=True)  
    room = serializers.PrimaryKeyRelatedField(read_only=True)  
    doctor = serializers.SerializerMethodField()
    content = serializers.CharField(required=False, allow_blank=True)
    image = serializers.ImageField(required=False)
    video = serializers.FileField(required=False)
    voice_message = serializers.FileField(required=False)
    
    class Meta:
        model = ChatMessage
        fields = ['id', 'room', 'sender', 'content', 'timestamp', 'is_read', 'doctor', 'image', 'video', 'voice_message']

    def validate(self, data):
        content = data.get('content', '').strip()
        has_attachments = any([
            data.get('image'),
            data.get('video'),
            data.get('voice_message')
        ])
        
        if not content and not has_attachments:
            raise serializers.ValidationError("Content or at least one attachment is required.")
        return data

    def get_doctor(self, obj):
        if obj.room and obj.room.doctor:
            return {
                'first_name': obj.room.doctor.first_name,
                'profile_pic': obj.room.doctor.profile_pic.url if obj.room.doctor.profile_pic else None
            }
        return None

    def validate_image(self, value):
        if value and not value.name.endswith(('jpg', 'jpeg', 'png', 'gif')):
            raise serializers.ValidationError('Unsupported image file type.')
        return value

    def validate_video(self, value):
        if value and not value.name.endswith(('mp4', 'avi', 'mov')):
            raise serializers.ValidationError('Unsupported video file type.')
        return value

    def validate_voice_message(self, value):
        if value and not value.name.endswith(('webm', 'mp3', 'wav', 'ogg')):
            raise serializers.ValidationError('Unsupported audio file type.')
        return value


    
    
    





