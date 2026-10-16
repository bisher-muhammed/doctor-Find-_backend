from decimal import Decimal
from django.db import models
from Users.models import MyUser
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from Users.models import Wallet
from django.db.models import Q





class DoctorProfile(models.Model):
    user = models.OneToOneField(MyUser, on_delete=models.CASCADE, related_name='doctorprofile')

    first_name = models.CharField(max_length=10, null=True,blank =True)
    last_name = models.CharField(max_length=10, null= True,blank=True)
    specification = models.CharField(max_length=100,null=True,blank= True)
    bio = models.TextField()
    experience = models.IntegerField(default=0)
    profile_pic = models.ImageField(upload_to='doctor/profile_pic', blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    



    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.specification})"


    


    
    




class Slots(models.Model):
    doctor = models.ForeignKey(
        "DoctorProfile",
        on_delete=models.CASCADE,
        related_name="slots",
    )

    start_time = models.DateTimeField()
    start_date = models.DateField()

    end_time = models.DateTimeField()
    end_date = models.DateField()
    duration = models.PositiveIntegerField()
    is_blocked = models.BooleanField(default=False)
    is_booked = models.BooleanField(default=False)
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal("0.00"),
    )

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def __str__(self):
        return (
            f"{self.doctor.user.username}: "
            f"{self.start_time.strftime('%I:%M %p')} - "
            f"{self.end_time.strftime('%I:%M %p')}"
        )

    


class Document(models.Model):
    doctor = models.ForeignKey(DoctorProfile,related_name='doctors',on_delete=models.CASCADE)
    file = models.FileField(upload_to='media/doctor/documents')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    

    def __str__(self):
        return f"{self.file.name} uploaded by {self.doctor.user.username}"




from django.db import models

class Bookings(models.Model):
    AWAITING_PAYMENT = "awaiting_payment"
    PENDING = "pending"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

    STATUS_CHOICES = [
        (AWAITING_PAYMENT, "Awaiting Payment"),
        (PENDING, "Pending"),
        (COMPLETED, "Completed"),
        (CANCELLED, "Cancelled"),
        (EXPIRED, "Expired"),
    ]

    ACTIVE_STATUSES = (
        AWAITING_PAYMENT,
        PENDING,
    )

    VISIBLE_STATUSES = (
        PENDING,
        COMPLETED,
        CANCELLED,
        EXPIRED
        
    )

    user = models.ForeignKey(
        MyUser,
        on_delete=models.CASCADE,
    )

    doctor = models.ForeignKey(
        "DoctorProfile",
        on_delete=models.CASCADE,
        related_name="booking",
    )
    slots = models.ForeignKey(
        Slots,
        on_delete=models.PROTECT,
        related_name="bookings",
    )

    idempotency_key = models.UUIDField(
        null=True,
        blank=True,
    )

    payment_method = models.CharField(
        max_length=20,
        choices=[
            ("wallet", "Wallet"),
            ("razorpay", "Razorpay"),
        ],
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=AWAITING_PAYMENT,
    )

    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "idempotency_key"],
                condition=Q(idempotency_key__isnull=False),
                name="unique_booking_idempotency_per_user",
            ),
            models.UniqueConstraint(
                fields=["slots"],
                condition=Q(
                    status__in=["awaiting_payment", "pending"]
                ),
                name="unique_active_booking_per_slot",
            ),
        ]

        indexes = [
            models.Index(
                fields=["user", "-created_at"],
                name="booking_user_created_idx",
            ),
            models.Index(
                fields=["status", "expires_at"],
                name="booking_status_expiry_idx",
            ),
        ]

    def reservation_expired(self, now=None):
        if self.status != self.AWAITING_PAYMENT:
            return False

        if now is None:
            now = timezone.now()

        return self.expires_at is None or self.expires_at <= now

    def __str__(self):
        return (
            f"Booking {self.pk} - {self.user} - "
            f"{self.slots} - {self.status}"
        )




class Transaction(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE, related_name='transaction')
    booking = models.ForeignKey(Bookings, on_delete=models.SET_NULL, null=True, blank=True) 
    payment_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)
    razorpay_refund_id = models.CharField(max_length=100, null=True, blank=True)
    currency = models.CharField(max_length=10, default='INR')
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refund_pending', 'Refund Pending'),
        ("refund_processing", "Refund Processing"),
        ('refunded', 'Refunded'),
        ("refund_failed", "Refund Failed"),
    ], default='pending')
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))  
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    refund_idempotency_key = models.CharField(max_length=64,unique=True,null=True,blank=True,)



    def save(self, *args, **kwargs):
        # Snapshot the slot amount only when creating this transaction.
        if self._state.adding and self.booking_id and self.booking.slots_id:
            self.amount = self.booking.slots.amount

        super().save(*args, **kwargs)


    def __str__(self):
        return f"Transaction {self.payment_id} - {self.currency} - Amount: {self.amount}"





from django.db import models
from django.conf import settings  

class WalletTransaction(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="wallet_transactions",
    )

    wallet = models.ForeignKey(
        "Users.Wallet",
        on_delete=models.CASCADE,
        related_name="transactions",
    )

    booking = models.ForeignKey(
        Bookings,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    payment_id = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )

    currency = models.CharField(
        max_length=10,
        default="INR",
    )

    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("completed", "Completed"),
            ("failed", "Failed"),
            ("refund_pending", "Refund Pending"),
            ("refund_processing", "Refund Processing"),
            ("refunded", "Refunded"),
            ("refund_failed", "Refund Failed"),
        ],
        default="pending",
    )

    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal("0.00"),
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    refund_idempotency_key = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
    )

    def save(self, *args, **kwargs):
        if (
            self._state.adding
            and self.booking_id
            and self.amount == Decimal("0.00")
        ):
            self.amount = self.booking.slots.amount

        super().save(*args, **kwargs)

    def __str__(self):
        return (
            f"Wallet Transaction {self.payment_id} - "
            f"{self.currency} - Amount: {self.amount}"
        )



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


