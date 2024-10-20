from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Wallet, MyUser
from django.contrib.auth import get_user_model
from Doctors.models import Bookings,Notification
from django.utils import timezone
from asgiref.sync import async_to_sync
from Backend.sockets import sio 

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
def notify_doctor_slot_booking(sender, instance, created, **kwargs):
    if created:
        slot = instance.slots
        doctor = instance.doctor
        notification_message = (
            f"{instance.user.username} has booked a slot. "
            f"Slot: {slot.start_time} - {slot.end_time}, "
            f"Date: {slot.start_date}"
        )

        # Convert datetime objects to strings (ISO 8601 format)
        slot_start = slot.start_time.isoformat() if slot.start_time else None
        slot_end = slot.end_time.isoformat() if slot.end_time else None
        timestamp = timezone.now().isoformat()  # Current timestamp in ISO format

        print(f"Notification Message: {notification_message}")
        print(f"Slot Start (ISO format): {slot_start}")
        print(f"Slot End (ISO format): {slot_end}")
        print(f"Timestamp: {timestamp}")

        Notification.create_notification(recipient=doctor.user, message=notification_message)
        print('notification created')

        # Emit the notification via Socket.IO to the relevant room
        room_id = f'doctor_{doctor.user.id}'
        print(f"Emitting to room ID: {room_id}")

        async_to_sync(sio.emit)(
            'receive_notification',
            {
                'message': notification_message,
                'slot_start': slot_start,
                'slot_end': slot_end,
                'timestamp': timestamp  # Already in string format
            },
            room=room_id
        )
        print("Notification emitted successfully!")


        unread_count = Notification.objects.filter(recipient=doctor.user, is_read=False).count()
        print(unread_count)
        async_to_sync(sio.emit)(
            'unread_count_update',
            {
                'unread_count': unread_count
            },
            room=room_id  # Send the count to the relevant user
        )




