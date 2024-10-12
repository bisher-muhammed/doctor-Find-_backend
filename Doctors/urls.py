from django.urls import path
from.views import * 


urlpatterns = [

    
    # path('doctor/profile/', DoctorProfile_Create.as_view(), name='profile'),
    path('doctor/register/', DoctorRegisterView.as_view(), name='doctor_register'),
    path('doctor/otpverify/', OtpVerification.as_view(), name='otp_verify'),
    path('doctor/forgotpassword/', ForgotPassword.as_view(), name='forgotpassword'),
    path('doctor/change-password/<int:id>/', ChangePassword.as_view(), name='change_password'),
    path('doctor/login/', DoctorLoginView.as_view(), name='doctor_login'),
    path('doctor/resend_otp/',ResendOtpView.as_view(),name='resend_otp'),
    path('doctor/generate_slots/', GenerateSlots.as_view(), name='generate_slots'),
    path('doctor/slots/', SlotListView.as_view(), name='slots'),  
    
    path('doctor/single_slot/<int:slot_id>/', EditSlot.as_view(), name='edit-slot'),
    path('doctor/delete_slot/<int:slot_id>/', DeleteSlotView.as_view(), name='delete_slot'),

    path('doctor/edit_profile/', EditDoctorProfileView.as_view(), name='edit_profile'),
    path('doctor/doctor_details/',DoctorProfileView.as_view(),name = 'doctor_details'),
    path('doctor/<int:doctor_id>/documents/',DocumentUpload.as_view(), name='documents'),
    path('doctor/bookings/',BookingList.as_view(),name='bookings'),
    path('bookings/<int:pk>/update/', update_booking_status, name='update-booking-status'),
    path('doctor/booking_detail/<int:pk>/', BookingDetail.as_view(), name='booking-detail'),    


    
    path('doctor/chat-rooms/', ChatRoomListView.as_view(), name='chat-room-list'),
    path('doctor/chat_rooms/<int:room_id>/messages/', ChatMessageListCreateView.as_view(), name='chatroom-detail'),
    path('doctor/chat_rooms/<int:room_id>/send_message/', DoctorSendMessageView.as_view(), name='doctor-send-message'),
    path('doctor/notification/',DotorNotification.as_view(),name='doctor-notifications'),
    path('doctor/notification/<int:notification_id>/', DotorNotification.as_view(), name='doctor-notification-detail'),  
    path('doctor/notification/unread-count/', UnreadNotificationCount.as_view(), name='unread_notification_count'),

]




    



