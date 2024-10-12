from datetime import timedelta,datetime
from venv import logger
from django.utils import timezone
from flask import Response
from grpclib import Status
from rest_framework import serializers,viewsets
from Users.models import MyUser  # Assuming this is the custom user model
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import DoctorProfile, Notification, Slots,Document

class DoctorRegisterSerializer(serializers.ModelSerializer):
    user_type = serializers.ChoiceField(choices=MyUser.USER_TYPE_CHOICES, default='doctor')

    class Meta:
        model = MyUser
        fields = ['id', 'username', 'email', 'phone_number', 'password', 'user_type']
        extra_kwargs = {
            'password': {'write_only': True},
            'user_type': {'read_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        validated_data['user_type'] = 'doctor'
        instance = self.Meta.model(**validated_data)

        if password is not None:
            instance.set_password(password)
        else:
            raise serializers.ValidationError({"password": "Password is required."})

        
        return instance


class DoctorLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        print("Validating data:", data)

        if not email or not password:
            raise serializers.ValidationError("Email and password are required")
        
        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid credentials')

        if not user.is_active:
            raise serializers.ValidationError('Account is blocked')

        print("User validated successfully.")
        return {
            'user': user,
            'email': email,
            'password': password,
        }


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        return token


class OtpVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)



from django.utils.timezone import make_aware, utc


class SlotCreateSerializer(serializers.ModelSerializer):
    start_time = serializers.DateTimeField()
    end_time = serializers.DateTimeField()
    start_date = serializers.DateField()
    end_date = serializers.DateField()

    class Meta:
        model = Slots
        fields = ['id', 'start_time', 'end_time', 'duration', 'start_date', 'end_date', 'is_blocked', 'doctor', 'is_booked','amount']
        
        read_only_fields = ['doctor','amount']

    def validate(self, data):
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        slot_duration = data.get('duration')
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        if not start_time or not end_time or slot_duration is None or not start_date or not end_date:
            raise serializers.ValidationError('Start time, end time, slot duration, start date, and end date must be provided.')

        if start_time >= end_time:
            raise serializers.ValidationError('End time must be after start time.')

        if slot_duration < 1:
            raise serializers.ValidationError('Duration must be at least 1 minute.')

        if start_time < timezone.now():
            raise serializers.ValidationError('Cannot create slots in the past.')

        doctor = self.context['request'].user.doctorprofile
        overlapping_slots = Slots.objects.filter(
            doctor=doctor,
            start_date__range=[start_date, end_date],  # Overlapping range of dates
            start_time__lt=end_time,                   # Existing slot starts before new slot ends
            end_time__gt=start_time                    # Existing slot ends after new slot starts
        )
        
        if overlapping_slots.exists():
            raise serializers.ValidationError('A slot with overlapping times already exists.')

        return data
    
    def calculate_amound(self,duration):
        base_amound = 200
        if duration <=30:
            return base_amound
        else:
            additional_time = duration -30
            additional_amount = (additional_time//30)*100
            return base_amound + additional_amount

    def create(self, validated_data):
        doctor = self.context['request'].user.doctorprofile  # Assign the doctor from the logged-in user's profile
        start_time = validated_data.get('start_time')
        end_time = validated_data.get('end_time')
        slot_duration = validated_data.get('duration')
        start_date = validated_data.get('start_date')
        end_date = validated_data.get('end_date')

        slots_created = 0
        current_date = start_date
        current_time = timezone.now()

        while current_date <= end_date:
            slot_start = timezone.make_aware(datetime.combine(current_date, start_time.time()), timezone.get_current_timezone())
            slot_end = timezone.make_aware(datetime.combine(current_date, end_time.time()), timezone.get_current_timezone())

            while slot_start < slot_end:
                slot_end_time = slot_start + timedelta(minutes=slot_duration)
                if slot_end_time > slot_end:
                    slot_end_time = slot_end

                if slot_start >= current_time:
                    if not Slots.objects.filter(
                        doctor=doctor,
                        start_time=slot_start,
                        end_time=slot_end_time,
                        duration=slot_duration,
                        start_date=start_date,
                        end_date=current_date
                    ).exists():
                        amount = self.calculate_amound(slot_duration)
                        new_slot = Slots(
                            doctor=doctor,
                            start_time=slot_start,
                            end_time=slot_end_time,
                            duration=slot_duration,
                            start_date=start_date,
                            end_date=current_date,
                            amount = amount
                        )
                        new_slot.save()
                        slots_created += 1

                slot_start = slot_end_time

            current_date += timedelta(days=1)

        return {
            'slots_created': slots_created
        }






from rest_framework import serializers
from .models import DoctorProfile, Document

class DocumentSerializer(serializers.ModelSerializer):
    doctor_username = serializers.CharField(source='doctor.user.username', read_only=True)
    doctor_specification = serializers.CharField(source='doctor.specification', read_only=True)
    doctor_id = serializers.IntegerField(source='doctor.id', read_only=True)
    is_verified = serializers.BooleanField(source='doctor.is_verified')

    class Meta:
        model = Document
        fields = ['id', 'file', 'uploaded_at', 'doctor_username', 'doctor_specification','doctor_id','is_verified']
    

    




class DoctorProfileSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    documents = DocumentSerializer(many=True, read_only=True)  # Assuming documents are read-only in this context
    slots = serializers.SerializerMethodField()  # Add this line
    is_active = serializers.SerializerMethodField()
    

    class Meta:
        model = DoctorProfile
        fields = [
            'username', 'email', 'phone_number',
            'id', 'first_name', 'last_name', 'specification',
            'bio', 'experience', 
            'is_verified',
            'profile_pic',
            'documents',
            'slots',
            'is_active',
        ]

    def get_username(self, obj):
        return obj.user.username

    def get_email(self, obj):
        return obj.user.email

    def get_phone_number(self, obj):
        return obj.user.phone_number
    
    def get_is_active(self,obj):
        return obj.user.is_active
    

    def get_slots(self, obj):
        slots = obj.slots.filter(start_time__gte=timezone.now()).order_by('start_time')
        return SlotCreateSerializer(slots, many=True).data

    def validate(self, data):
        required_fields = ['first_name', 'last_name', 'specification', 'bio', 'experience', 'available_from', 'available_to']
        for field in required_fields:
            if field not in data or not data.get(field):
                raise serializers.ValidationError({field: "This field is required."})

        if 'experience' in data:
            if not isinstance(data['experience'], int):
                raise serializers.ValidationError({'experience': 'Experience must be an integer.'})
            if data['experience'] < 0:
                raise serializers.ValidationError({'experience': 'Experience must be a positive integer.'})

        return data

    def create(self, validated_data):
        user = self.context['request'].user
        doctor_profile, created = DoctorProfile.objects.get_or_create(user=user, defaults=validated_data)
        if not created:
            for attr, value in validated_data.items():
                setattr(doctor_profile, attr, value)
            doctor_profile.save()
        return doctor_profile

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance



######################################################################################################################


from rest_framework.exceptions import ValidationError

from rest_framework.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime, timedelta
from .models import Slots, DoctorProfile

class SlotDeleteSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()

    class Meta:
        model = Slots
        fields = ['id']

    def validate(self, attrs):
        """
        Validate that the slot exists, is associated with the current user,
        and handle outdated slot cleanup by blocking them.
        """
        request = self.context['request']
        user = request.user
        slot_id = attrs.get('id')

        # Ensure current time is timezone-aware and convert to local time
        current_time_utc = timezone.now()
        current_time_local = timezone.localtime(current_time_utc)
        current_date_local = current_time_local.date()

        # Filter expired slots that are not booked and should be blocked
        expired_slots = Slots.objects.filter(
            start_time__lt=current_time_local,  # Start time has passed
            start_date__lte=current_date_local,  # Start date is today or earlier
            is_booked=False  # Ensure that only unbooked slots are considered expired
        )

        # Print debug information
        print(f"Expired slots query: {expired_slots.query}")
        print(f"Expired slots before update: {list(expired_slots)}")

        # Update expired slots to set is_blocked to True
        updated_count = expired_slots.update(is_blocked=True)
        print(f"Number of expired slots updated: {updated_count}")

        # Validate if the slot exists and is associated with the current user
        try:
            slot = Slots.objects.get(id=slot_id, doctor__user=user)
        except Slots.DoesNotExist:
            raise ValidationError('Slot not found or not associated with the current user.')

        return attrs

    def delete_slot(self):
        """
        Perform the actual deletion of the slot.
        """
        slot_id = self.validated_data['id']
        # Perform the actual deletion
        Slots.objects.filter(id=slot_id).delete()



    from django.middleware.csrf import CsrfViewMiddleware
    def _validate_csrf(self, request):
        """
        Validates the CSRF token.
        """
        try:
            csrf_middleware = CsrfViewMiddleware() # type: ignore
            csrf_middleware.process_view(request, None, (), {})
        except ValidationError as e:
            raise serializers.ValidationError('CSRF token missing or incorrect.') 
        


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'


