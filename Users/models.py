from django.db import models
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from django.conf import settings




class MyAccountManager(BaseUserManager):
    def create_user(self, username, email, phone_number, password=None):
        if not username:
            raise ValueError("User must have a username")
        if not email:
            raise ValueError("User must have an email address")
        if not phone_number:
            raise ValueError("User must have a phone number")
        if not password:
            raise ValueError("User must provide a password")

        # Validate the email address
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError as e:
            raise ValueError(f"Invalid email address: {e}")

        # Normalize the email address
        email = self.normalize_email(email)

        user = self.model(
            username=username,
            email=email,
            phone_number=phone_number
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, phone_number, password=None):
        user = self.create_user(
            username=username,
            email=self.normalize_email(email),
            phone_number=phone_number,
            password=password,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.user_type = 'admin'
        user.save(using=self._db)
        return user

    def create_doctor(self, username, email, phone_number, password=None):
        user = self.create_user(
            username=username,
            email=self.normalize_email(email),
            phone_number=phone_number,
            password=password,
        )
        user.user_type = 'doctor'
        user.save(using=self._db)
        return user

class MyUser(AbstractBaseUser):

    USER_TYPE_CHOICES =(
        ('admin','Admin'),
        ('patient','Patient'),
        ('doctor','Doctor')
    )
    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    date_joined = models.DateTimeField(verbose_name='date joined',auto_now=True)
    last_login = models.DateTimeField(verbose_name='last login',auto_now=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    otp = models.CharField(null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='patient')  


    objects = MyAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'phone_number']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

class UserProfile(models.Model):
    user = models.ForeignKey(MyUser,on_delete=models.CASCADE,related_name='User_profile')
    profile_pic = models.ImageField(upload_to='media/profile_pic', blank=True, null=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], blank=True)
    address = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True)




class Wallet(models.Model):
    user = models.OneToOneField(MyUser, on_delete=models.CASCADE,related_name="Wallet")
    balance = models.DecimalField(max_digits=10,decimal_places=2,default=0.00)
    booking_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)  # Track booking amounts

    

    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True)
    notifications = models.JSONField(default=list, blank=True) 

    def __str__(self):
        return f"{self.user.username}'s Wallet - Balance: {self.balance}"
    

    def add_notification(self, message):
        # Convert the timestamp to ISO format for JSON serialization
        message['timestamp'] = message['timestamp'].isoformat()  # Convert to string
        self.notifications.append(message)
        self.save()






    