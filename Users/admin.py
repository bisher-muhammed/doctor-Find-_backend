from django.contrib import admin

from Chat.models import ChatMessage
from .models import MyUser,UserProfile,Wallet
from Doctors.models import Slots,Document,DoctorProfile,Bookings,Transaction

admin.site.register(MyUser)
admin.site.register(UserProfile)
admin.site.register(Slots)
admin.site.register(Document)
admin.site.register(DoctorProfile)
admin.site.register(Bookings)
admin.site.register(Transaction)
admin.site.register(ChatMessage)
admin.site.register(Wallet)