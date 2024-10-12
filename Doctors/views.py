from django.utils import timezone
from datetime import datetime, timedelta
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from Users.utils import send_otp_via_email
from .serializers import *
from django.contrib.auth.hashers import make_password  # Import to hash the new password
from .models import Bookings, DoctorProfile, Document
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
import random
from.models import Slots
from django.utils import timezone
from rest_framework import generics
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.authentication import JWTAuthentication

from django.contrib.auth.decorators import login_required
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import get_user_model,authenticate
from Chat.serializers import ChatMessageSerializer,ChatRoomSerializer

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
                print("User account is blocked")
                return Response({'error': 'Blocked'}, status=status.HTTP_403_FORBIDDEN)
            

            elif user.user_type != 'doctor':
                print("User is not a doctor")
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
                    print("Login successful. Tokens generated.")
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
        
        serializer = DoctorRegisterSerializer(data=data)
        if serializer.is_valid():
            try:
                user = User(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    phone_number=serializer.validated_data['phone_number'],
                    user_type='doctor'
                )
                print(user)
                user.set_password(serializer.validated_data['password'])
                user.is_active = False
                otp = str(random.randint(1000, 9999))
                user.otp_expiry = timezone.now()+timedelta(minutes=1)
                user.otp = otp
                user.save()
                
                
                DoctorProfile.objects.get_or_create(user=user)
                send_otp_via_email(user.email, otp)

                response_data = {
                    'message': 'Otp sent successfully',
                    'email': user.email
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
            except Exception as e:
                print(f"Error in DoctorRegisterView: {e}")
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OtpVerification(APIView):
    def post(self, request):
        serializer = OtpVerificationSerializer(data=request.data)  # Ensure this serializer is defined and imported
        if serializer.is_valid():
            try:
                email = serializer.validated_data.get('email')
                entered_otp = serializer.validated_data.get('otp')
                user = User.objects.get(email=email)

                if user.otp == entered_otp and user.otp_expiry > timezone.now():
                    user.is_active = True
                    user.otp = None
                    user.otp_expiry = None
                    user.save()
                    return Response({'message': 'User registered and verified successfully'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'error': 'User not found or already verified'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                print(f"Error during OTP verification: {e}")
                return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
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
    
    def post(self,request,*args, **kwargs):
        user_id = self.kwargs.get('id')
        print(user_id)
        new_password = request.data.get('password')
        try:
            user = User.objects.get(id=user_id)
            user_password = make_password(new_password)
            user.password = user_password
            user.save()

            return Response({'success':True,'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error':'User not found'},status=status.HTTP_404_NOT_FOUND)
        

        
        
class ResendOtpView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if user.is_active:
                return Response({'error': 'User is already verified'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate a new OTP and set expiry
            otp = str(random.randint(1000, 9999))
            user.otp = otp
            user.otp_expiry = timezone.now() + timedelta(minutes=1)  # OTP valid for 5 minutes
            user.save()

            # Send OTP to the user's email
            send_otp_via_email(user.email, otp)

            return Response({'message': 'OTP resent successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error during OTP resend: {e}")
            return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

######################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################
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
    
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]
    serializer_class = SlotCreateSerializer
    def get_queryset(self):
        user = self.request.user
        
        try:
            # Corrected related_name to doctor_profile
            doctorprofile = user.doctorprofile
        except DoctorProfile.DoesNotExist:
            # Handle the case where the user does not have a doctor profile
            logger.error(f'User {user.username} does not have an associated doctor profile.')
            return Slots.objects.none()

        # Continue filtering the queryset
        start_date_str = self.request.query_params.get('start_date')
        end_date_str = self.request.query_params.get('end_date')

        queryset = Slots.objects.filter(doctor=doctorprofile, is_blocked=False)

        if start_date_str and end_date_str:
            try:
                start_date = timezone.make_aware(datetime.strptime(start_date_str, "%Y-%m-%d"))
                end_date = timezone.make_aware(datetime.strptime(end_date_str, "%Y-%m-%d"))
                queryset = queryset.filter(start_date__gte=start_date, start_date__lte=end_date)
            except ValueError:
                logger.error("Invalid date format provided")

        current_time = timezone.now()
        outdated_slots = Slots.objects.filter(
            start_time__lt=current_time,
            start_date__lte=current_time.date()
        )
        outdated_count = outdated_slots.count()
        outdated_slots.delete()
        logger.info(f"Deleted {outdated_count} outdated slots")

        logger.debug(f'User: {user.username}')
        logger.debug(f'Doctor Profile: {doctorprofile}')
        logger.debug(f'Queryset: {queryset}')

        return queryset



from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view
from Users.serializers import BookingSerializer




class DeleteSlotView(generics.GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
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
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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



class EditDoctorProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

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
    permission_classes = [permissions.IsAuthenticated]
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
    permission_classes = [permissions.IsAuthenticated]
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


        


from django.utils import timezone
from datetime import timedelta

class BookingList(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer

    def get_queryset(self):
        user = self.request.user

        # Ensure the user is a doctor and fetch the doctor's profile
        try:
            doctor_profile = DoctorProfile.objects.get(user=user)
        except DoctorProfile.DoesNotExist:
            return Bookings.objects.none()  # Return an empty queryset if the user is not a doctor

        # Filter bookings where the logged-in doctor is assigned
        bookings = Bookings.objects.filter(doctor=doctor_profile)

        # Print for debugging purposes
        print(f"Doctor: {doctor_profile.user.email}")
        print(f"Bookings: {bookings}")

        return bookings



@api_view(['PATCH'])
def update_booking_status(request, pk):
    try:
        booking = Bookings.objects.get(pk=pk)
    except Bookings.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = BookingSerializer(booking, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
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


class ChatRoomListView(generics.ListAPIView):
    serializer_class = ChatRoomSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        queryset = ChatRoom.objects.none()  # Start with an empty queryset

        # Check if the user is a doctor
        if hasattr(user, 'doctorprofile'):
            queryset = ChatRoom.objects.filter(doctor=user.doctorprofile)

            # Retrieve the search term from the query parameters
            search_term = self.request.query_params.get('search', None)
            
            # If a search term exists, filter chat rooms by doctor's first name
            if search_term:
                queryset = queryset.filter(
                    Q(doctor__first_name__icontains=search_term)
                )

        return queryset
    
    
from django.shortcuts import get_object_or_404


class ChatMessageListCreateView(generics.ListCreateAPIView):
    serializer_class = ChatMessageSerializer
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]

    def get(self, request):
        unread_count = Notification.objects.filter(recipient=request.user, is_read=False).count()
        return Response({'unread_count': unread_count})
