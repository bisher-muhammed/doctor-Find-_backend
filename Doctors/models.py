from decimal import Decimal
from django.db import models
from Users.models import MyUser
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from Users.models import Wallet





class DoctorProfile(models.Model):
    user = models.OneToOneField(MyUser, on_delete=models.CASCADE, related_name='doctorprofile')

    first_name = models.CharField(max_length=10, null=True,blank =True)
    last_name = models.CharField(max_length=10, null= True,blank=True)
    specification = models.CharField(max_length=100,null=True,blank= True)
    bio = models.TextField()
    experience = models.IntegerField(default=0)
    profile_pic = models.ImageField(upload_to='media/doctor/profile_pic', blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    



    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.specification})"


    


    
    


class Slots(models.Model):
    doctor = models.ForeignKey('DoctorProfile', on_delete=models.CASCADE, related_name='slots')
    start_time = models.DateTimeField()
    start_date = models.DateField()
    end_time = models.DateTimeField()
    duration = models.PositiveIntegerField()  # Add duration field here
    is_blocked = models.BooleanField(default=False)
    is_booked = models.BooleanField(default=False)
    amount = models.DecimalField(max_digits=10,decimal_places=2,default=Decimal('0.00'))


    end_date = models.DateField()

    def save(self, *args, **kwargs):
        # Convert duration to hours if it's 60 minutes or more
        if self.duration >= 60:
            self.duration = timedelta(minutes=self.duration).total_seconds() / 3600  # Convert to hours

        super(Slots, self).save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.doctor.user.username}: {self.start_time.strftime('%I:%M %p')} - {self.end_time.strftime('%I:%M %p')}"
    


class Document(models.Model):
    doctor = models.ForeignKey(DoctorProfile,related_name='doctors',on_delete=models.CASCADE)
    file = models.FileField(upload_to='media/doctor/documents')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    

    def __str__(self):
        return f"{self.file.name} uploaded by {self.doctor.user.username}"




from django.db import models

class Bookings(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('cancelled', 'Cancelled'),
        ('completed', 'Completed'),
    ]
    
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    doctor = models.ForeignKey('DoctorProfile', on_delete=models.CASCADE, related_name='booking')
    slots = models.OneToOneField(Slots, on_delete=models.CASCADE,related_name='bookings')
    created_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    
    def __str__(self):
        return f"Booking by {self.user.username} with {self.doctor.user.username} on {self.slots.start_time}"
    



class Transaction(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE,related_name='transaction')
    booking = models.ForeignKey(Bookings, on_delete=models.CASCADE, null=True, blank=True)
    payment_id=models.CharField(max_length=100,null=True,blank=True)
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)
    
    currency = models.CharField(max_length=10, default='INR')  # Default to INR for Indian Rupees
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Transaction {self.payment_id} - {self.currency}"
    




from django.db import models
from django.conf import settings  # For referencing AUTH_USER_MODEL

class WalletTransaction(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    wallet = models.ForeignKey('Users.Wallet', on_delete=models.CASCADE, related_name='transactions')  # Correct reference to Wallet in Users app
    currency = models.CharField(max_length=10, default='INR')  # Default to INR
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # ForeignKey to User and Booking
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet_transactions')
    booking = models.ForeignKey(Bookings, on_delete=models.CASCADE, null=True, blank=True)

    payment_id = models.CharField(max_length=100, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f" - Status: {self.status}"



class Notification(models.Model):
    recipient = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Notification for {self.recipient.username} at {self.created_at}"
    

    

    @classmethod
    def create_notification(cls, recipient, message):
        # Create a new notification instance
        notification = cls(recipient=recipient, message=message)
        notification.save()  # Save to the database
        return notification






    
    @classmethod
    def clear_notifications(cls, doctor):
        """
        Clear all notifications for the doctor.
        """
        cls.objects.filter(recipient=doctor).delete()  # Use recipient instead of doctor

    @classmethod
    def mark_notification_as_read(cls, doctor, notification_id):
        """
        Mark a notification as read based on its ID.
        """
        try:
            notification = cls.objects.get(id=notification_id, recipient=doctor)  # Use recipient instead of doctor
            notification.is_read = True
            notification.save()
        except cls.DoesNotExist:
            print(f"Notification with ID {notification_id} does not exist for doctor {doctor.username}.")


