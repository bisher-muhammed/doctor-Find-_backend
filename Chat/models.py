from django.db import models
from django.conf import settings
from Users.models import MyUser
from Doctors.models import  DoctorProfile

class ChatRoom(models.Model):
    patient = models.ForeignKey(MyUser, related_name='patient_rooms', on_delete=models.CASCADE, limit_choices_to={'user_type': 'patient'})
    doctor = models.ForeignKey(DoctorProfile, related_name='doctor_rooms', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ChatRoom({self.patient.username} - {self.doctor.first_name})"

class ChatMessage(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    date = models.DateTimeField(auto_now_add=True)
    doctor = models.ForeignKey(DoctorProfile, on_delete=models.CASCADE, null=True, blank=True)



    image = models.ImageField(upload_to='media/doctor/chat_images/', null=True, blank=True)
    video = models.FileField(upload_to='media/doctor/chat_videos/', null=True, blank=True)
    voice_message = models.FileField(upload_to='media/doctor/chat_voice_messages/', null=True, blank=True)




    def __str__(self):
        return f"Message by {self.sender.username} in {self.room}"




