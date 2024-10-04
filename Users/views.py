
import random
from django.utils import timezone
from django.shortcuts import get_object_or_404
from datetime import timedelta
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from rest_framework.generics import ListAPIView,CreateAPIView,RetrieveAPIView
from Doctors.serializers import DoctorProfileSerializer,SlotCreateSerializer
import razorpay
from django.conf import settings
from Doctors.models import Transaction, WalletTransaction
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest, JsonResponse
from rest_framework.decorators import api_view
from .serializers import WalletSerializer
from .models import Wallet




from Doctors.models import DoctorProfile,Slots,Bookings
from .models import UserProfile  # Ensure UserProfile is imported
from .utils import send_otp_via_email, send_verification
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print("Login attempts:", request.data)

        serializer = UserLoginSerializer(data=request.data)
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

            else:
                if not user.is_staff:
                    print("User is not staff; processing tokens")
                    UserProfile.objects.get_or_create(user=user)
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




class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        required_fields = ['username', 'email', 'phone_number', 'password']
        if not all(field in data for field in required_fields):
            return Response({'detail': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserRegisterSerializer(data=data)
        if serializer.is_valid():
            try:
                user = User(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    phone_number=serializer.validated_data['phone_number']
                )
                user.set_password(serializer.validated_data['password'])
                user.is_active = False
                otp = str(random.randint(1000, 9999))
                user.otp = otp
                user.otp_expiry = timezone.now()+timedelta(minutes=1)

                user.save()
                
                UserProfile.objects.get_or_create(user=user)
                send_otp_via_email(user.email, otp)

                response_data = {
                    'message': 'OTP sent successfully.',
                    'email': user.email
                }
                return Response(response_data, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"Error during user registration: {e}")
                return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            print(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Otpverification(APIView):
    def post(self, request):
        serializer = OtpVerificationSerializer(data=request.data)
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
            print("otp re_sended",otp)

            return Response({'message': 'OTP resent successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error during OTP resend: {e}")
            return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


                
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "UserProfile not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Use a serializer that includes profile details
        serializer = UserProfileDetailSerializer(user_profile)
        return Response(serializer.data)

class EditProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({'error': "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data)


    def put(self, request):
            try:
                user_profile = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                return Response({'error': "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)

            serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            print("error",serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

#######################################################################################################################################################

class Doctors_list(ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    serializer_class = DoctorProfileSerializer

    def get_queryset(self):
        # This method should return the queryset for the view
        queryset = DoctorProfile.objects.filter(is_verified=True)
        
        return queryset

    def get(self, request, *args, **kwargs):
        # This method handles GET requests
        queryset = self.get_queryset()
        
        
        serializer = self.get_serializer(queryset, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)


class SlotListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SlotCreateSerializer

    def get_queryset(self):
        doctor_id = self.kwargs.get('doctor_id')
        print(f"Requested doctor ID: {doctor_id}")

        try:
            doctor = DoctorProfile.objects.get(id=doctor_id)
            if doctor.is_verified:
                slots = Slots.objects.filter(doctor=doctor,is_booked= False)
                
                
                return slots
            else:
                return Slots.objects.none()
        except DoctorProfile.DoesNotExist:
            return Slots.objects.none()
        
    def get(self, request, *args, **kwargs):
        doctor_id = self.kwargs.get('doctor_id')

        try:
            doctor = DoctorProfile.objects.get(id=doctor_id)
        except DoctorProfile.DoesNotExist:
            return Response({'detail': 'Doctor not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the doctor is verified
        if not doctor.is_verified:
            return Response({'detail': 'Doctor is not verified.'}, status=status.HTTP_404_NOT_FOUND)

        # Fetch the slots for the doctor
        slots = self.get_queryset()

        # Serialize the doctor profile
        doctor_serializer = DoctorProfileSerializer(doctor)
        print(f"Doctor Profile Serialized Data: {doctor_serializer.data}")

        # Serialize the slots
        slot_serializer = self.get_serializer(slots, many=True)
        

        # Combine the data
        response_data = {
            'doctor': doctor_serializer.data,
            'slots': slot_serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)


        
    
class BookSlotView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, doctor_id, slot_id):
        try:
            # Print the entire request data to debug the payment method issue
            

            # Retrieve the doctor and slot based on the provided IDs
           
            doctor = DoctorProfile.objects.get(id=doctor_id)

            
            slot = Slots.objects.get(id=slot_id, doctor=doctor, is_booked=False, is_blocked=False)

            # Get the payment method from the request
            payment_method = request.data.get('payment_method', 'razorpay')  # Default to Razorpay if not provided
            

            # Create a new booking instance
            booking = Bookings.objects.create(user=request.user, doctor=doctor, slots=slot)
            print(f"Created booking: {booking.id} for user: {request.user.username}")

            if payment_method == 'wallet':
               
                
                # Retrieve or create the user's wallet
                wallet, created = Wallet.objects.get_or_create(user=request.user)

                
                    

                # Check if the wallet balance is sufficient
                
                if wallet.balance < slot.amount:
                    print("Insufficient wallet balance.")
                    return Response({"error": "Insufficient wallet balance."}, status=status.HTTP_400_BAD_REQUEST)

                # Deduct the slot amount from the wallet
                
                wallet.balance -= slot.amount
                wallet.save()

                # Create a wallet transaction
                wallet_transaction = WalletTransaction.objects.create(
                    wallet=wallet,
                    user=request.user,
                    booking=booking,
                    payment_id=None,  # Set payment_id to None for now
                    currency='INR',
                    status='completed',  # Assuming the payment is successful
                )

                

                # Update the booking status to completed
                booking.status = 'pending'
                booking.save()
                booking.slots.is_booked = True
                booking.slots.save()
                

                # Prepare response data
                response_data = {
                    'message': "Booking confirmed and payment completed.",
                    'amount': slot.amount,
                    'currency': 'INR',
                    'booking_id': booking.id,
                    'wallet_transaction': str(wallet_transaction),
                }

                print(f"Returning successful wallet payment response: {response_data}")
                return Response(response_data, status=status.HTTP_201_CREATED)

            else:  # Razorpay payment option
                print("Processing Razorpay payment.")
                # Razorpay payment setup
                client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                amount = slot.amount  # Slot amount to be used for payment creation

                # Create Razorpay order
                order_data = {
                    'amount': int(amount * 100),  # Razorpay accepts amount in paise
                    'currency': 'INR',
                    'payment_capture': '1'
                }
                razorpay_order = client.order.create(data=order_data)

                print(f"Razorpay order created with ID: {razorpay_order['id']}")

                # Create a transaction instance with the Razorpay order ID
                transaction = Transaction.objects.create(
                    user=request.user,
                    booking=booking,
                    razorpay_order_id=razorpay_order['id'],
                    currency='INR',
                    status='pending'  # Set as pending until payment is completed
                )

                print(f"Transaction created with Razorpay order ID: {razorpay_order['id']} and transaction ID: {transaction.id}")

                # Prepare response data for Razorpay payment
                response_data = {
                    'razorpay_order_id': razorpay_order['id'],
                    'razorpay_key_id': settings.RAZORPAY_KEY_ID,
                    'amount': slot.amount,
                    'currency': 'INR',
                    'booking_id': booking.id,
                    'wallet_transaction': None,  # No wallet transaction for Razorpay payment
                }

                print(f"Returning Razorpay payment response: {response_data}")
                return Response(response_data, status=status.HTTP_201_CREATED)

        except DoctorProfile.DoesNotExist:
            print("Doctor not found.")
            return Response({"error": "Doctor not found."}, status=status.HTTP_404_NOT_FOUND)
        except Slots.DoesNotExist:
            print("Slot not found or already booked.")
            return Response({"error": "Slot not found or already booked."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)










    

        
    
from django.views.decorators.csrf import csrf_exempt
import json



@csrf_exempt
def payment_callback(request):
    if request.method == "POST":
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

        # Parse the request body if it's JSON
        try:
            data = json.loads(request.body.decode('utf-8'))
        except json.JSONDecodeError:
            return HttpResponseBadRequest("Invalid JSON data.")

        # Extract payment details
        try:
            razorpay_payment_id = data['razorpay_payment_id']
            razorpay_order_id = data['razorpay_order_id']
            razorpay_signature = data['razorpay_signature']
            booking_id = data['booking_id']
        except KeyError as e:
            return HttpResponseBadRequest(f"Missing field: {str(e)}")

        # Retrieve the transaction using the Razorpay order ID
        try:
            transaction = Transaction.objects.get(razorpay_order_id=razorpay_order_id)
        except Transaction.DoesNotExist:
            return HttpResponseBadRequest("Transaction not found.")

        # Verify the payment signature
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }

        try:
            client.utility.verify_payment_signature(params_dict)
            # Payment is valid
            transaction.payment_id = razorpay_payment_id
            transaction.razorpay_signature = razorpay_signature
            transaction.status = 'completed'  # Changed from 'successful' to 'completed'
            transaction.save()

            # Mark booking as completed
            transaction.booking.status = 'pending'
            transaction.booking.slots.is_booked = True  # Mark the slot as booked
            transaction.booking.slots.save()
            transaction.booking.save()

            # Send verification email or confirmation
            send_verification(
                email=transaction.booking.user.email,
                doctor_name=f"{transaction.booking.doctor.first_name} {transaction.booking.doctor.last_name}",
                start_time=transaction.booking.slots.start_time,
                end_time=transaction.booking.slots.end_time,
                duration=transaction.booking.slots.duration,
                date=transaction.booking.slots.start_date,
                transaction=transaction  # Pass the transaction object
            )

            # Respond with success message
            return JsonResponse({"message": "Payment verified successfully."}, status=status.HTTP_200_OK)

        except razorpay.errors.SignatureVerificationError:
            # Invalid signature - mark transaction as failed
            transaction.status = 'failed'
            transaction.save()
            return HttpResponseBadRequest("Payment verification failed.")


        

    

@api_view(['PATCH'])
def update_status(request, pk):
    try:
        booking = Bookings.objects.get(pk=pk)
    except Bookings.DoesNotExist:
        return Response({'error': 'Booking not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    # Validate that 'status' is in the request data
    if 'status' not in request.data:
        return Response({'error': 'Status field is required.'}, status=status.HTTP_400_BAD_REQUEST)

    serializer = BookingSerializer(booking, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MyAppointments(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer
    def get_queryset(self):
        user = self.request.user
        return Bookings.objects.filter(user=user)


class WalletDetailView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WalletSerializer

    def retrieve(self, request, *args, **kwargs):
        wallet = self.get_object()  # Get the wallet instance
        wallet_serializer = self.get_serializer(wallet)
        return Response({
            'wallet': wallet_serializer.data,
            'notifications': wallet.notifications[-2:],  # Get the last 5 notifications
        })

    def get_object(self):
        user = self.request.user
        return Wallet.objects.get(user=user)
    



class WalletPaymentCallbackView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        booking_id = request.data.get('booking_id')
        print('booking_id:', booking_id)

        try:
            # Retrieve the booking instance for the user
            booking = get_object_or_404(Bookings, id=booking_id, user=request.user)
            print('Booking:', booking)

            # If the booking is already completed, return a message
            if booking.status == 'pending':
                return Response({"message": "This booking is already completed."}, status=status.HTTP_200_OK)

            # Retrieve the wallet transaction related to the booking using the get() method
            wallet_transaction = WalletTransaction.objects.get(booking__id=booking_id, user=request.user)
            print('Wallet Transaction:', wallet_transaction)

            # Ensure the wallet transaction exists and hasn't been completed yet
            if wallet_transaction:
                # Mark the booking slot as booked
                wallet_transaction.booking.slots.is_booked = True
                wallet_transaction.booking.slots.save()

                # Update the wallet transaction status to completed
                wallet_transaction.status = 'completed'
                wallet_transaction.save()

                # Mark the booking as completed
                wallet_transaction.booking.status = 'pending'
                wallet_transaction.booking.save()

                # Optional: Send a confirmation email
                # send_booking_confirmation_email(request.user, booking)

                return Response({"message": "Booking confirmed and payment completed."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "The transaction has already been completed."}, status=status.HTTP_400_BAD_REQUEST)

        except WalletTransaction.DoesNotExist:
            return Response({"error": "Wallet transaction not found."}, status=status.HTTP_404_NOT_FOUND)
        except Bookings.DoesNotExist:
            return Response({"error": "Booking not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





