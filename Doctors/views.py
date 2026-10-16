from django.utils import timezone
from datetime import datetime, timedelta
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from Doctors.booking_service import cancel_appointment_service
from Users.utils import send_otp_via_email
from .serializers import *
from django.contrib.auth.hashers import make_password  # Import to hash the new password
from .models import Bookings, DoctorProfile, Document, Transaction
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
import random
from.models import Slots
from django.db.models import Count,Sum
from decimal import Decimal
from django.db.models.functions import TruncDate, TruncMonth
from django.utils import timezone
from rest_framework import generics
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db import IntegrityError

from django.contrib.auth.decorators import login_required
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import get_user_model,authenticate
from Chat.serializers import ChatMessageSerializer,ChatRoomSerializer
from Users.permissions import IsDoctor, IsPatient

User = get_user_model()


class DoctorLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):

        print("Login attempts:", request.data)

        serializer = DoctorLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')

            print(f"Validating user with email:", email)

            user = authenticate(username=email, password=password)  # Ensure the username is correctly mapped to email
            print('Authenticated user:', user)

            if user is None:
                print("Authentication failed: Invalid credentials")
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

            elif not user.is_active:
                
                return Response({'error': 'Blocked'}, status=status.HTTP_403_FORBIDDEN)
            

            elif user.user_type != 'doctor':
                
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

            else:
                if not user.is_staff:
                    print("User is not staff; processing tokens")
                    DoctorProfile.objects.get_or_create(user=user)
                    refresh = RefreshToken.for_user(user)
                    refresh['username'] = str(user.username)

                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)

                    content = {
                        'userid': user.id,
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'isAdmin': user.is_superuser,
                    }
                    
                    return Response(content, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'This account is not a user account'}, status=status.HTTP_401_UNAUTHORIZED)
                
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DoctorRegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        print(data)

        required_fields = ['username', 'email', 'phone_number', 'password']
        if not all(field in data for field in required_fields):
            return Response({'detail': "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user already exists and is active
        username = data.get('username')
        email = data.get('email')
        phone_number = data.get('phone_number')
        
        # Check for existing active users
        existing_user = User.objects.filter(
            username=username,
            is_active=True
        ).first()
        
        if existing_user:
            return Response({
                'error': 'User already exists and is verified',
                'detail': 'A verified account with this username already exists. Please try logging in instead.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check for existing email
        existing_email = User.objects.filter(
            email=email,
            is_active=True
        ).first()
        
        if existing_email:
            return Response({
                'error': 'Email already registered',
                'detail': 'A verified account with this email already exists. Please try logging in instead.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check for existing phone number
        existing_phone = User.objects.filter(
            phone_number=phone_number,
            is_active=True
        ).first()
        
        if existing_phone:
            return Response({
                'error': 'Phone number already registered',
                'detail': 'A verified account with this phone number already exists. Please try logging in instead.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle case where user registered but not verified (inactive)
        # Check by email, username, or phone number
        inactive_user = User.objects.filter(
            models.Q(username=username) | models.Q(email=email) | models.Q(phone_number=phone_number),
            is_active=False
        ).first()
        
        if inactive_user:
            # Update the user details with new data if they're different
            # This allows users to modify their details before verification
            inactive_user.username = username
            inactive_user.email = email  
            inactive_user.phone_number = phone_number
            inactive_user.set_password(data.get('password'))
            
            # Generate new OTP (always generate new one for better UX)
            otp = str(random.randint(1000, 9999))
            inactive_user.otp = otp
            inactive_user.otp_expiry = timezone.now() + timedelta(minutes=5)  # Extended to 5 minutes
            inactive_user.save()
            
            try:
                send_otp_via_email(inactive_user.email, otp)
                return Response({
                    'message': 'Registration continued - OTP sent',
                    'email': inactive_user.email,
                    'detail': 'We found your previous registration. A new OTP has been sent to complete your verification.',
                    'redirect_to_otp': True  # This tells frontend to redirect to OTP page
                }, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"Error sending OTP: {e}")
                return Response({
                    'error': 'Failed to send OTP',
                    'detail': 'Please try again later.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Create new user
        serializer = DoctorRegisterSerializer(data=data)
        if serializer.is_valid():
            try:
                user = User(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    phone_number=serializer.validated_data['phone_number'],
                    user_type='doctor'
                )
                user.set_password(serializer.validated_data['password'])
                user.is_active = False
                otp = str(random.randint(1000, 9999))
                user.otp_expiry = timezone.now() + timedelta(minutes=5)  # Extended to 5 minutes for better UX
                user.otp = otp
                user.save()
                
                DoctorProfile.objects.get_or_create(user=user)
                send_otp_via_email(user.email, otp)

                response_data = {
                    'message': 'Registration successful - OTP sent',
                    'email': user.email,
                    'detail': 'Please check your email for the verification code.',
                    'redirect_to_otp': True  # This tells frontend to redirect to OTP page
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
                
            except IntegrityError as e:
                # Handle database integrity errors
                print(f"IntegrityError in DoctorRegisterView: {e}")
                if 'username' in str(e):
                    return Response({
                        'error': 'Username already exists',
                        'detail': 'Please choose a different username.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                elif 'email' in str(e):
                    return Response({
                        'error': 'Email already registered',
                        'detail': 'Please use a different email address.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                elif 'phone_number' in str(e):
                    return Response({
                        'error': 'Phone number already registered',
                        'detail': 'Please use a different phone number.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({
                        'error': 'Registration failed',
                        'detail': 'User with these credentials already exists.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
            except Exception as e:
                print(f"Error in DoctorRegisterView: {e}")
                return Response({
                    'error': 'Registration failed',
                    'detail': 'An unexpected error occurred. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OtpVerification(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = OtpVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                email = serializer.validated_data.get('email')
                entered_otp = serializer.validated_data.get('otp')
                
                user = User.objects.get(email=email, is_active=False)
                
                if not user.otp:
                    return Response({
                        'error': 'No OTP found',
                        'detail': 'Please request a new OTP.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if user.otp_expiry and user.otp_expiry <= timezone.now():
                    return Response({
                        'error': 'OTP expired',
                        'detail': 'Your OTP has expired. Please request a new one.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if user.otp == entered_otp:
                    user.is_active = True
                    user.otp = None
                    user.otp_expiry = None
                    user.save()
                    return Response({
                        'message': 'User registered and verified successfully',
                        'detail': 'Your account has been activated. You can now log in.'
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'Invalid OTP',
                        'detail': 'The OTP you entered is incorrect. Please try again.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found',
                    'detail': 'No unverified user found with this email address.'
                }, status=status.HTTP_404_NOT_FOUND)
                
            except Exception as e:
                print(f"Error during OTP verification: {e}")
                return Response({
                    'error': 'Verification failed',
                    'detail': 'An unexpected error occurred. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPassword(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            otp = str(random.randint(1000, 9999))
            print("Generated OTP:", otp)
            # Set OTP expiry time (e.g., 10 minutes from now)
            otp_expiry = timezone.now() + timedelta(minutes=10)
            send_otp_via_email(user.email, otp)
            user.otp = otp
            user.otp_expiry = otp_expiry
            user.save()

            response_data = {
                'message': 'OTP sent successfully',
                'email': user.email,
                'user_id': user.id,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'exists': False, 'message': 'Invalid Email'}, status=status.HTTP_404_NOT_FOUND)


class ChangePassword(APIView):

    def post(self, request, *args, **kwargs):
        user_id = self.kwargs.get('id')
        print(user_id)
        new_password = request.data.get('password')

        # Validation checks
        if not new_password or len(new_password) < 8:
            return Response({'error': 'Password must be at least 8 characters long.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.search(r'[A-Z]', new_password):
            return Response({'error': 'Password must contain at least one uppercase letter.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.search(r'\d', new_password):
            return Response({'error': 'Password must contain at least one digit.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            return Response({'error': 'Password must contain at least one special character.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user_password = make_password(new_password)
            user.password = user_password
            user.save()

            return Response({'success': True, 'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        
class ResendOtpView(APIView):
    """
    View to resend OTP for unverified users
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response({
                'error': 'Email required',
                'detail': 'Please provide your email address.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email, is_active=False)
            
            # Generate new OTP
            otp = str(random.randint(1000, 9999))
            user.otp = otp
            user.otp_expiry = timezone.now() + timedelta(minutes=1)
            user.save()
            
            send_otp_via_email(user.email, otp)
            
            return Response({
                'message': 'OTP resent successfully',
                'email': user.email,
                'detail': 'A new OTP has been sent to your email.'
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'error': 'User not found',
                'detail': 'No unverified user found with this email address.'
            }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            print(f"Error resending OTP: {e}")
            return Response({
                'error': 'Failed to resend OTP',
                'detail': 'Please try again later.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import Slots, DoctorProfile

from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework import status
from .serializers import SlotCreateSerializer
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView,ListAPIView,RetrieveAPIView



import logging

logger = logging.getLogger(__name__)

class GenerateSlots(CreateAPIView):
    queryset = Slots.objects.all()
    serializer_class = SlotCreateSerializer
    
    permission_classes = [IsDoctor]

    def post(self, request, *args, **kwargs):
        # Initialize the serializer with the provided data
        serializer = self.get_serializer(data=request.data, context={'request': request})
        
        # Validate the data and handle creation
        if serializer.is_valid():
            result = serializer.save()
            return Response({
                'status': 'success',
                'message': f"{result['slots_created']} slots successfully created"
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'status': 'error',
                'message': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)



from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import Slots

from django.utils import timezone
import logging

logger = logging.getLogger(__name__)




class SlotListView(generics.ListAPIView):
    permission_classes = [IsDoctor]
    serializer_class = SlotCreateSerializer

    def get_queryset(self):
        user = self.request.user

        try:
            doctorprofile = user.doctorprofile
        except DoctorProfile.DoesNotExist:
            logger.error(
                f"User {user.username} does not have an associated doctor profile."
            )
            return Slots.objects.none()

        start_date_str = self.request.query_params.get("start_date")
        end_date_str = self.request.query_params.get("end_date")

        current_time = timezone.now()

        # Only fetch this doctor's slots.
        # Do not delete historical slots from the database.
        queryset = Slots.objects.filter(
            doctor=doctorprofile,
            is_blocked=False,
            start_time__gte=current_time,
        )

        # Optional date filtering
        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(
                    start_date_str, "%Y-%m-%d"
                ).date()
                end_date = datetime.strptime(
                    end_date_str, "%Y-%m-%d"
                ).date()

                queryset = queryset.filter(
                    start_date__range=(start_date, end_date)
                )

            except ValueError:
                logger.warning("Invalid date format provided")

        logger.debug(f"User: {user.username}")
        logger.debug(f"Doctor Profile: {doctorprofile}")
        logger.debug(f"Queryset: {queryset.query}")

        return queryset.order_by("start_time")




from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view
from Users.serializers import BookingSerializer




class DeleteSlotView(generics.GenericAPIView):
    
    permission_classes = [IsDoctor]
    serializer_class = SlotDeleteSerializer

    def delete(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.delete_slot()
                return Response({'status': 'success', 'message': 'Slot successfully deleted'}, status=status.HTTP_200_OK)
            except ValidationError as e:
                return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Slots.DoesNotExist:
                return Response({'status': 'error', 'message': 'Slot not found or already deleted'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                logger.error(f"Error deleting slot: {str(e)}")
                return Response({'status': 'error', 'message': 'An error occurred while deleting the slot'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)








logger = logging.getLogger(__name__)

class EditSlot(APIView):
    
    permission_classes = [IsDoctor]

    def get_slot(self, slot_id, user):
        try:
            return Slots.objects.get(id=slot_id, doctor__user=user)
        except Slots.DoesNotExist:
            return None

    def get(self, request, slot_id):
        slot = self.get_slot(slot_id, request.user)
        if slot is None:
            return Response({'error': 'Slot does not exist'}, status=status.HTTP_404_NOT_FOUND)
        serializer = SlotCreateSerializer(slot)
        return Response(serializer.data)

    def patch(self, request, slot_id):
        slot = self.get_slot(slot_id, request.user)
        if slot is None:
            return Response({"error": "Slot not found"}, status=status.HTTP_404_NOT_FOUND)

        logger.info(f"Request data: {request.data}")

        start_time_str = request.data.get('start_time')
        end_time_str = request.data.get('end_time')
        slot_duration = request.data.get('duration')
        end_date_str = request.data.get('end_date')

        if not start_time_str or not end_time_str or slot_duration is None or not end_date_str:
            return Response({
                'status': 'error',
                'message': 'Start time, end time, slot duration, and end date must be provided.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Convert the start and end times from 12-hour format to datetime objects
            start_time = timezone.make_aware(
                datetime.combine(
                    timezone.localtime().date(),
                    datetime.strptime(start_time_str, "%I:%M %p").time()
                )
            )
            end_time = timezone.make_aware(
                datetime.combine(
                    timezone.localtime().date(),
                    datetime.strptime(end_time_str, "%I:%M %p").time()
                )
            )

            # Convert end_date from string to date object
            end_date = timezone.make_aware(datetime.strptime(end_date_str, "%Y-%m-%d"))

            if start_time >= end_time:
                return Response({
                    'status': 'error',
                    'message': 'End time must be after start time.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Update the slot with new details
            slot.start_time = start_time
            slot.end_time = end_time
            slot.duration = slot_duration
            slot.end_date = end_date
            slot.save()

            return Response({
                'status': 'success',
                'message': 'Slot successfully updated'
            }, status=status.HTTP_200_OK)

        except ValueError as e:
            return Response({
                'status': 'error',
                'message': f'Invalid date/time format: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsPatient])
def active_reservation(request):
    now = timezone.now()

    bookings = (
        Bookings.objects.filter(
            user=request.user,
            status="awaiting_payment",
            expires_at__gt=now,
        )
        .select_related("slots")
        .prefetch_related("transaction_set")
        .order_by("-created_at")
    )

    for booking in bookings:
        transaction = (
            booking.transaction_set
            .filter(status="pending")
            .order_by("-created_at")
            .first()
        )

        if not transaction or not transaction.razorpay_order_id:
            continue

        # Adjust "doctor_id" if your Slots model uses another relation.
        doctor_id = booking.slots.doctor_id

        return Response({
            "has_reservation": True,
            "booking_id": booking.id,
            "doctor_id": doctor_id,
            "slot_id": booking.slots_id,
            "expires_at": booking.expires_at.isoformat(),
            "remaining_seconds": max(
                0,
                int(
                    (booking.expires_at - now).total_seconds()
                ),
            ),
            "razorpay_order_id": transaction.razorpay_order_id,
            "razorpay_key_id": settings.RAZORPAY_KEY_ID,
            "amount": str(transaction.amount),
            "currency": transaction.currency,
        })

    return Response({
        "has_reservation": False,
    })




class EditDoctorProfileView(APIView):
    permission_classes = [IsDoctor]
    

    def get(self, request):
        try:
            doctor_profile = DoctorProfile.objects.get(user=request.user)
            print(f"DoctorProfile fetched successfully for user: {request.user.email}")
        except DoctorProfile.DoesNotExist:
            return Response({'error': 'DoctorProfile does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = DoctorProfileSerializer(doctor_profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request):
        try:
            doctor_profile = DoctorProfile.objects.get(user=request.user)
            print(f"Attempting to fetch DoctorProfile for user: {request.user.email}")
        except DoctorProfile.DoesNotExist:
            return Response({'error': 'DoctorProfile does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        print(f"Request data: {request.data}")  # Debugging incoming data
        serializer = DoctorProfileSerializer(doctor_profile, data=request.data, partial=True)
        if serializer.is_valid():
            print("Serializer is valid. Saving data...")  # Debugging serializer
            serializer.save()
            print(f"Updated profile data: {serializer.data}")  # Debugging updated data
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            print(f"Serializer errors: {serializer.errors}")  # Debugging validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DoctorProfileView(APIView):
    permission_classes = [IsDoctor]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        try:
            print(f"Fetching DoctorProfile for user: {request.user}")  # Debugging user
            doctor_profile = DoctorProfile.objects.get(user=request.user)
            print("DoctorProfile fetched successfully.")  # Debugging profile fetch
        except DoctorProfile.DoesNotExist:
            print("DoctorProfile does not exist for this user.")  # Debugging error
            return Response({"error": "Doctor profile not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = DoctorProfileSerializer(doctor_profile)
        print(f"Serialized data: {serializer.data}")  # Debugging serialized data
        return Response(serializer.data, status=status.HTTP_200_OK)



logger = logging.getLogger(__name__)

class DocumentUpload(APIView):
    permission_classes = [IsDoctor]
    parser_classes = [MultiPartParser]  # Handle multipart form data

    def post(self, request, doctor_id: int) -> Response:
        try:
            # Check if doctor exists
            doctor = DoctorProfile.objects.get(id=doctor_id)
            files = request.FILES.getlist('file')
            
            if not files:
                return Response({'error': 'No files were uploaded.'}, status=status.HTTP_400_BAD_REQUEST)

            # Create Document instances
            document_objects = [
                Document(
                    doctor=doctor,
                    file=file
                   
                )
                for file in files
            ]

            # Bulk create documents
            Document.objects.bulk_create(document_objects)

            # Success response
            return Response(
                {'message': 'Documents uploaded successfully. Please wait for verification.'},
                status=status.HTTP_201_CREATED
            )

        except DoctorProfile.DoesNotExist:
            # Doctor not found
            return Response({'error': 'Doctor not found.'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            # General error
            logger.error(f"Exception occurred while uploading documents: {e}")
            return Response({'error': 'An error occurred while processing your request.'}, status=status.HTTP_400_BAD_REQUEST)


        





from django.utils.dateparse import parse_date

class BookingList(ListAPIView):
    permission_classes = [IsDoctor]
    serializer_class = BookingSerializer

    def get_queryset(self):
        user = self.request.user

        try:
            doctor_profile = DoctorProfile.objects.get(user=user)
        except DoctorProfile.DoesNotExist:
            return Bookings.objects.none()

        queryset = Bookings.objects.filter(doctor=doctor_profile)

        # Search patient details
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(user__username__icontains=search) |
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search)
            )

        # Date filter
        start_date_str = self.request.query_params.get('start_date')
        end_date_str = self.request.query_params.get('end_date')

        if start_date_str and end_date_str:
            try:
                start_date = parse_date(start_date_str)
                end_date = parse_date(end_date_str)

                if not start_date or not end_date:
                    raise ValidationError("Invalid date format. Use YYYY-MM-DD.")

                if start_date > end_date:
                    raise ValidationError("Start date must be less than or equal to end date.")

                queryset = queryset.filter(created_at__date__range=(start_date, end_date))

            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(f"Date filtering error: {str(e)}")

        # Status filter
        status = self.request.query_params.get('status')
        if status in ['pending', 'cancelled', 'completed']:
            queryset = queryset.filter(status=status)

        return queryset.order_by('-created_at')



@api_view(["PATCH"])
@permission_classes([IsDoctor])
def update_booking_status(request, pk):
    # Find the booking and verify doctor ownership.
    booking = get_object_or_404(
        Bookings.objects.select_related("doctor", "slots"),
        pk=pk,
    )

    if booking.doctor.user_id != request.user.id:
        return Response(
            {"error": "You are not authorized to update this appointment."},
            status=status.HTTP_403_FORBIDDEN,
        )

    new_status = request.data.get("status")

    if not new_status:
        return Response(
            {"error": "Status is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # This list must match the actual statuses in your model.
    allowed_statuses = {
        Bookings.COMPLETED,
        Bookings.CANCELLED,
    }

    if new_status not in allowed_statuses:
        return Response(
            {"error": "Invalid appointment status."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Handle cancellation through the service.
    # Do not directly save CANCELLED here because cancellation
    # may require a payment refund and slot release.
    if new_status == Bookings.CANCELLED:
        result = cancel_appointment_service(
            booking_id=booking.pk,
            user=request.user,
            actor_type="doctor",
        )

        if result["result"] == "not_found":
            return Response(
                {"error": "Appointment not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if result["result"] == "not_eligible":
            return Response(
                {"error": result.get("message", "This appointment cannot be cancelled.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if result["result"] == "payment_pending":
            return Response(
                {
                    "error": result.get(
                        "message",
                        "The refund or payment reconciliation is still pending.",
                    ),
                    "refund_status": result.get("refund_status"),
                },
                status=status.HTTP_202_ACCEPTED,
            )

        if result["result"] == "refund_failed":
            return Response(
                {
                    "error": "The refund failed. Please contact support.",
                    "refund_status": result.get("refund_status"),
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if result["result"] == "already_cancelled":
            booking.refresh_from_db()
            return Response(
                {
                    "message": "This appointment has already been cancelled.",
                    "data": BookingSerializer(booking).data,
                    "refund_status": result.get("refund_status"),
                },
                status=status.HTTP_200_OK,
            )

        if result["result"] == "cancelled":
            booking.refresh_from_db()
            return Response(
                {
                    "message": "Appointment cancelled successfully.",
                    "data": BookingSerializer(booking).data,
                    "refund_status": result.get("refund_status"),
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"error": "Unable to process the cancellation."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if new_status == Bookings.COMPLETED:
        if booking.status != Bookings.PENDING:
            return Response(
                {"error": "Only pending appointments can be completed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = BookingSerializer(
            booking,
            data={"status": new_status},
            partial=True,
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {
                "message": "Appointment marked as completed.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class BookingDetail(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer
    queryset = Bookings.objects.all()

    def get_object(self):
        user = self.request.user
        booking_id = self.kwargs.get('pk')

        try:
            booking = Bookings.objects.get(id=booking_id)
        except Bookings.DoesNotExist:
            raise Exception("Booking not found.")

        # Debugging info
        print(f"Logged-in user: {user.username} (ID: {user.id})")
        print(f"Booking details: ID: {booking.id}, Doctor: {booking.doctor.id}, Patient: {booking.user.id}")

        # Check if the user is a doctor and is associated with this booking
        if hasattr(user, 'doctorprofile') and booking.doctor == user.doctorprofile:
            print(f"Doctor {user.username} is associated with booking ID {booking_id}.")
            return booking

        # Check if the user is the patient associated with this booking
        if booking.user == user:
            print(f"Patient {user.username} is associated with booking ID {booking_id}.")
            return booking

        print(f"User {user.username} is NOT associated with booking ID {booking_id}.")
        raise PermissionDenied("You do not have permission to view this booking.")


#---------------------------------------------------------------------------------------------------------------------------#
from Chat.models import *  
from rest_framework.exceptions import NotFound
from django.db.models import Q
import logging

class ChatRoomListView(generics.ListAPIView):
    serializer_class = ChatRoomSerializer
    permission_classes = [IsDoctor]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'doctorprofile'):
            return ChatRoom.objects.filter(doctor=user.doctorprofile)
        return ChatRoom.objects.none()  # Return empty queryset if user is not a doctor
from django.shortcuts import get_object_or_404
    
from django.shortcuts import get_object_or_404


class ChatMessageListCreateView(generics.ListCreateAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = [IsDoctor]

    def get_queryset(self):
        room_id = self.kwargs['room_id']
        user = self.request.user

        # Get the doctor's profile based on the authenticated user
        doctor_profile = get_object_or_404(DoctorProfile, user=user)

        # Ensure the doctor is part of the chat room
        room = get_object_or_404(ChatRoom, id=room_id, doctor=doctor_profile)

        # Return all messages from that room
        return ChatMessage.objects.filter(room=room)

    def perform_create(self, serializer):
        room_id = self.kwargs['room_id']
        user = self.request.user

        # Get the doctor's profile based on the authenticated user
        doctor_profile = get_object_or_404(DoctorProfile, user=user)

        # Fetch the room to ensure the doctor is part of it
        room = get_object_or_404(ChatRoom, id=room_id, doctor=doctor_profile)

        # Save the message with the doctor as the sender
        serializer.save(sender=self.request.user, room=room)
    

    
from django.core.exceptions import PermissionDenied
class DoctorSendMessageView(generics.CreateAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = [IsDoctor]
    parser_classes = [MultiPartParser, FormParser]  # To handle file uploads

    def perform_create(self, serializer):
        room_id = self.kwargs.get('room_id')
        user = self.request.user
        
        # Ensure the user is a doctor and retrieve the corresponding DoctorProfile
        doctor_profile = get_object_or_404(DoctorProfile, user=user)

        # Ensure the doctor is part of the chat room
        room = get_object_or_404(ChatRoom, id=room_id, doctor=doctor_profile)

        content = self.request.data.get('content', '').strip()

        # Check if there are attachments like image, video, or voice_message
        has_attachments = any([
            self.request.FILES.get('image'),
            self.request.FILES.get('video'),
            self.request.FILES.get('voice_message')
        ])

        # Ensure that either content or an attachment is provided
        if not content and not has_attachments:
            raise ValidationError("Content or at least one attachment is required.")

        # Save the message with the doctor as the sender
        serializer.save(sender=user, room=room)



class DotorNotification(ListAPIView):
    permission_classes = [IsDoctor]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        # Return notifications for the logged-in doctor
        return Notification.objects.filter(recipient=self.request.user).order_by('-created_at')
    


    

    
    

    

    def patch(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id, recipient=request.user)
            notification.is_read = True
            notification.save()
            return Response({'status': 'Notification marked as read'}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request):
        Notification.clear_notifications(request.user)
        return Response({'status': 'All notifications cleared'}, status=status.HTTP_204_NO_CONTENT)
    

        

class UnreadNotificationCount(APIView):
    permission_classes = [IsDoctor]

    def get(self, request):
        unread_count = Notification.objects.filter(recipient=request.user, is_read=False).count()
        return Response({'unread_count': unread_count})



def get_booking_statistics(doctor):
    """
    Returns booking and available-slot statistics.
    Accepts a DoctorProfile instance.
    """

    bookings = Bookings.objects.filter(doctor=doctor)
    slots = Slots.objects.filter(doctor=doctor)

    return {
        "total_bookings": bookings.count(),

        "available_slots": slots.filter(
            is_blocked=False,
            is_booked=False,
        ).count(),

        "completed_bookings": bookings.filter(
            status=Bookings.COMPLETED,
        ).count(),

        "cancelled_bookings": bookings.filter(
            status=Bookings.CANCELLED,
        ).count(),

        "pending_bookings": bookings.filter(
            status=Bookings.PENDING,
        ).count(),
    }


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsDoctor])
def doctor_dashboard_analytics(request):

    try:
        doctor = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return Response(
            {"error": "Doctor profile not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    today = timezone.localdate()

    # 30-day daily analytics, including today
    daily_start = today - timedelta(days=29)

    # Start of the current month and the preceding 11 months
    monthly_start = (
        today.replace(day=1) - timedelta(days=330)
    ).replace(day=1)

    # Booking statistics
    booking_stats = get_booking_statistics(doctor)

    # Today's appointments
    today_appointments = Bookings.objects.filter(
    doctor=doctor,
    slots__start_date=today,
).count()

    # Revenue transactions belonging to this doctor
    transactions = Transaction.objects.filter(
        booking__doctor=doctor,
        created_at__date__gte=monthly_start,
        created_at__date__lte=today,
    )

    # Overall transaction summary for the selected period
    summary = transactions.aggregate(
        total_transactions=Count("id"),

        successful_transactions=Count(
            "id",
            filter=Q(status="completed"),
        ),

        pending_transactions=Count(
            "id",
            filter=Q(status="pending"),
        ),

        failed_transactions=Count(
            "id",
            filter=Q(status="failed"),
        ),

        total_revenue=Sum(
            "amount",
            filter=Q(status="completed"),
        ),
    )

    summary["total_revenue"] = str(
        summary["total_revenue"] or Decimal("0.00")
    )

    # Daily revenue analytics
    daily_data = (
        transactions
        .filter(created_at__date__gte=daily_start)
        .annotate(period=TruncDate("created_at"))
        .values("period")
        .annotate(
            total_transactions=Count("id"),
            successful_transactions=Count(
                "id",
                filter=Q(status="completed"),
            ),
            pending_transactions=Count(
                "id",
                filter=Q(status="pending"),
            ),
            failed_transactions=Count(
                "id",
                filter=Q(status="failed"),
            ),
            revenue=Sum(
                "amount",
                filter=Q(status="completed"),
            ),
        )
        .order_by("period")
    )

    # Monthly revenue analytics
    monthly_data = (
        transactions
        .annotate(period=TruncMonth("created_at"))
        .values("period")
        .annotate(
            total_transactions=Count("id"),
            successful_transactions=Count(
                "id",
                filter=Q(status="completed"),
            ),
            pending_transactions=Count(
                "id",
                filter=Q(status="pending"),
            ),
            failed_transactions=Count(
                "id",
                filter=Q(status="failed"),
            ),
            revenue=Sum(
                "amount",
                filter=Q(status="completed"),
            ),
        )
        .order_by("period")
    )

    def format_rows(rows, monthly=False):
        return [
            {
                "period": row["period"].strftime(
                    "%Y-%m" if monthly else "%Y-%m-%d"
                ),
                "total_transactions": row["total_transactions"],
                "successful_transactions": row[
                    "successful_transactions"
                ],
                "pending_transactions": row["pending_transactions"],
                "failed_transactions": row["failed_transactions"],
                "revenue": str(
                    row["revenue"] or Decimal("0.00")
                ),
            }
            for row in rows
        ]

    return Response({
        "booking_statistics": {
            **booking_stats,
            "today_appointments": today_appointments,
        },
        "revenue_analytics": {
            "summary": summary,
            "daily": format_rows(daily_data),
            "monthly": format_rows(monthly_data, monthly=True),
            "currency": "INR",
        },
    })
