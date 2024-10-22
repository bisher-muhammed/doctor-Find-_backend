from django.urls import path
from .views import *



urlpatterns = [
    path('resend_otp/', ResendOtpView.as_view(), name='resend_otp'),
    path('signup/', RegisterView.as_view(), name='signup'),

    path ('login/',LoginView.as_view(), name ='login'),
    path('otpverify/',Otpverification.as_view(),name="otp_verify"),
    path ('changePassword/<int:id>/',ChangePassword.as_view(),name='changePassword'),
    path('fpassword/',ForgotPassword.as_view(),name='fpassword'),
    path('user_details/',UserProfileView.as_view(),name='user_detials'),
    path('edit_profile/', EditProfileView.as_view(), name='edit_profile'),
    path('doctors_list/',Doctors_list.as_view(),name='doctors_list'),
    path('available_slots/<int:doctor_id>/', SlotListView.as_view(), name='available_slots'),
    
    path('book-slot/<int:doctor_id>/<int:slot_id>/', BookSlotView.as_view(), name='book_slot'),
    path('my-appointments/', MyAppointments.as_view(), name='my_appointments'),
    path('verify-payment/', payment_callback, name='payment_callback'),
    path('bookings/<int:pk>/update/', update_status, name='update_booking_status'),
    path('wallet_view/',WalletDetailView.as_view(),name='Wallet_view'),
    path('wallet_payment/',WalletPaymentCallbackView.as_view(),name='Wallet_view')






    
]

