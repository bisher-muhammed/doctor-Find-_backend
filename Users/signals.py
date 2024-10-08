from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Wallet, MyUser
from django.contrib.auth import get_user_model
from Doctors.models import Bookings,Notification
from django.utils import timezone

User = get_user_model()  # Corrected to call the function

@receiver(post_save, sender=User)
def create_user_wallet(sender, instance, created, **kwargs):  # Fixed 'instnce' to 'instance'
    if created and instance.user_type == 'patient':
        Wallet.objects.get_or_create(user=instance)  # Fixed 'instnce' to 'instance'

@receiver(post_save, sender=Bookings)
def update_wallet_on_cancel(sender, instance, created, **kwargs):
    if not created:  # Only update for existing bookings
        if instance.status.lower() == 'cancelled':
            wallet, _ = Wallet.objects.get_or_create(user=instance.user)
            wallet.booking_amount = instance.slots.amount 
            wallet.balance += wallet.booking_amount # Assuming slots.amount is the booking amount
            wallet.save()



            message = {
                'text':f"₹{instance.slots.amount}added to your wallet",
                'timestamp':timezone.now()
            }
            wallet.add_notification(message)




@receiver(post_save, sender=Bookings)
def send_notification_to_doctor(sender, instance, created, **kwargs):
    if created:
        # Avoid circular import issue by importing sio inside the function
        from Backend.asgi import sio

        # Get the related doctor, user, and slot
        doctor = instance.doctor
        user = instance.user
        slot = instance.slots

        # Create a notification
        Notification.create_notification(
            doctor=doctor,
            user=user,
            slot=slot,
            status=instance.status
        )

        # Prepare the notification message
        notification_message = (
            f"You have a new booking!\n"
            f"User: {user.username}\n"
            f"Slot: {slot.start_time.strftime('%I:%M %p')} - {slot.end_time.strftime('%I:%M %p')}\n"
            f"Date: {slot.start_date.strftime('%Y-%m-%d')}\n"
            f"Status: {instance.status}"
        )

        # Emit real-time notification using the doctor’s ID as the room ID
        sio.start_background_task(sio.emit, 'send_notification', {
            'doctor_id': doctor.id,
            'notification_type': 'booking',
            'message': notification_message,
        }, room=f"doctor_{doctor.id}")
