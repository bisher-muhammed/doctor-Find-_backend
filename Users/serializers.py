from django.forms import ValidationError
from rest_framework import serializers
from .models import MyUser,UserProfile, Wallet
from datetime import date
from Doctors.models import Bookings, Transaction, WalletTransaction
from django.contrib.auth import get_user_model,authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
User = get_user_model()
from Doctors.serializers import DoctorProfileSerializer, SlotCreateSerializer



class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        # ...

        return token
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ('password',)





class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number','password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user_type = validated_data.get('user_type', 'patient')
        instance = self.Meta.model(**validated_data)

        if password is not None:
            instance.set_password(password)
            instance.save()
            
            return instance
        else:
            raise serializers.ValidationError({"password": "Password is required."})


class OtpVerificationSerializer(serializers.Serializer):
    email=serializers.EmailField()
    otp=serializers.CharField(max_length=6)



class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        print("Validating data:", data)

        if not email or not password:
            raise serializers.ValidationError('Email and password are required')

        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid credentials')

        if not user.is_active:
            raise serializers.ValidationError('Account is blocked')

        print("User validated successfully.")
        return data



class UserProfileDetailSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = '__all__'

    def get_user(self, obj):
        user = obj.user
        return {
            'username': user.username,
            'email': user.email,
            'phone_number': user.phone_number,
        }
    
    def get_is_active(self,obj):
        return obj.user.is_active


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ['phone_number', 'username', 'email'] 


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'

    def validate_first_name(self, value):
        """Ensure first name is alphabetic and not too short."""
        if not value.isalpha():
            raise serializers.ValidationError("First name should contain only alphabetic characters.")
        if len(value) < 2:
            raise serializers.ValidationError("First name must be at least 2 characters long.")
        return value

    def validate_last_name(self, value):
        """Ensure last name is alphabetic and not too short."""
        if not value.isalpha():
            raise serializers.ValidationError("Last name should contain only alphabetic characters.")
        if len(value) < 2:
            raise serializers.ValidationError("Last name must be at least 2 characters long.")
        return value

    def validate_date_of_birth(self, value):
        """Ensure date of birth is a valid past date."""
        if value and value > date.today():
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        return value

    def validate_gender(self, value):
        """Ensure gender is one of the allowed choices."""
        valid_genders = ['Male', 'Female', 'Other']
        if value not in valid_genders:
            raise serializers.ValidationError("Invalid gender choice.")
        return value

    def validate_postal_code(self, value):
        """Ensure postal code is numeric and of appropriate length."""
        if not value.isdigit():
            raise serializers.ValidationError("Postal code should contain only digits.")
        if len(value) not in [5, 6, 10]:
            raise serializers.ValidationError("Postal code must be 5, 6, or 10 digits long.")
        return value

    def validate_city(self, value):
        """Ensure city name is alphabetic."""
        if not value.isalpha():
            raise serializers.ValidationError("City name should contain only alphabetic characters.")
        return value

    def validate_state(self, value):
        """Ensure state name is alphabetic."""
        if not value.isalpha():
            raise serializers.ValidationError("State name should contain only alphabetic characters.")
        return value

    def validate_country(self, value):
        """Ensure country name is alphabetic."""
        if not value.isalpha():
            raise serializers.ValidationError("Country name should contain only alphabetic characters.")
        return value

    def validate_address(self, value):
        """Ensure address is not empty and not too long."""
        if len(value) < 5:
            raise serializers.ValidationError("Address must be at least 5 characters long.")
        if len(value) > 255:
            raise serializers.ValidationError("Address cannot be longer than 255 characters.")
        return value

    def validate(self, data):
        """Perform additional cross-field validation if needed."""
        # For example, you could ensure city, state, and country fields are all filled out together
        if any(field in data for field in ['city', 'state', 'country']):
            if not all(data.get(field) for field in ['city', 'state', 'country']):
                raise serializers.ValidationError("City, state, and country must all be provided together.")
        return data




class BookingSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    doctor = DoctorProfileSerializer()
    slots = SlotCreateSerializer()
    transaction_type = serializers.SerializerMethodField()# Declare it here

    class Meta:
        model = Bookings
        fields = ['id', 'user', 'doctor', 'slots', 'created_at', 'status','transaction_type']

    

    def get_transaction_type(self, obj):
    # Check if a Razorpay transaction exists
        if obj.transaction_set.exists():  # Use transaction_set to access related transactions
            return 'Razorpay'
        elif obj.wallettransaction_set.exists():  # Use wallettransaction_set for wallet transactions
            return 'Wallet'
        return 'Unknown'  # Return 'Unknown' if no transaction exists




from rest_framework import serializers

class TransactionSerializer(serializers.ModelSerializer):
    amount = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            'id',
            'user',
            'booking',
            'razorpay_order_id',
            'payment_id',
            'razorpay_signature',
            'status',
            'amount',  # Include the amount from the related slot
            'created_at',
            'updated_at'
        ]

    def get_amount(self, obj):
        # Access the slot through the booking and return the amount
        if obj.booking and obj.booking.slots:
            return obj.booking.slots.amount
        return None


class WalletSerializer(serializers.ModelSerializer):
    user = UserSerializer()  # Define UserSerializer as a field in WalletSerializer

    class Meta:
        model = Wallet
        fields = ['balance', 'user', 'created_at', 'updated_at','notifications','booking_amount']





class WalletTransactionSerializer(serializers.ModelSerializer):
    amount = serializers.SerializerMethodField()

    class Meta:
        model = WalletTransaction
        fields = [
            'id',
            'user',
            'wallet',
            'booking',
            'payment_id',
            'status',
            'amount',
            'created_at'
        ]

    def get_amount(self, obj):
        # Access the slot through the booking and return the amount
        if obj.booking and obj.booking.slots:
            return obj.booking.slots.amount
        return None
    

