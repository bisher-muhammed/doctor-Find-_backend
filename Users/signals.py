from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Wallet, MyUser
from django.contrib.auth import get_user_model
from Doctors.models import Bookings
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