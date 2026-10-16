from decimal import Decimal, InvalidOperation
import json
import secrets
import uuid
import random
import logging
from rest_framework.exceptions import ValidationError

from django.utils import timezone
from rest_framework import status
from django.utils.dateparse import parse_date
from django.shortcuts import get_object_or_404
from datetime import timedelta
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from Chat.models import ChatRoom
from rest_framework.permissions import AllowAny
from django.contrib.auth.hashers import make_password, check_password
from django.db import transaction, IntegrityError
from razorpay.errors import SignatureVerificationError

from Doctors.booking_service import BookingError, cancel_appointment_service, confirm_razorpay_payment, confirm_wallet_topup, create_wallet_topup_order, ensure_razorpay_order, lock_slot_and_booking, razorpay_client, refund_payment, reserve_slot, to_paise

from .serializers import *
from rest_framework.generics import ListAPIView,CreateAPIView,RetrieveAPIView
from Doctors.serializers import DoctorProfileSerializer,SlotCreateSerializer
from django.db.models import Q
from django.conf import settings
from Doctors.models import Notification, Transaction, WalletTransaction
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest, JsonResponse
from rest_framework.decorators import api_view,permission_classes
from .serializers import WalletSerializer
from .models import Wallet, WalletTopUp
import razorpay




from Doctors.models import DoctorProfile,Slots,Bookings
from .models import UserProfile  # Ensure UserProfile is imported
from .utils import *
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from.permissions import IsPatient
from django.core.cache import cache

User = get_user_model()
logger = logging.getLogger(__name__)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        logger.info("Login attemptsssssss: %s", request.data)


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
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        data = serializer.validated_data
        email = data["email"].strip().lower()
        username = data["username"]

        # Never reuse an existing account, even if it is inactive.
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {"email": ["This email is already registered."]},
                status=status.HTTP_400_BAD_REQUEST
            )

        
        otp = f"{secrets.randbelow(1_000_000):06d}"
        print(f"Generated OTP for {email}: {otp}")


        pending_data = {
            "username": username,
            "email": email,
            "phone_number": data["phone_number"],

            # Store the Django password hash, not the raw password.
            "password": make_password(data["password"]),

            # Store a hash of the OTP, not the OTP itself.
            "otp_hash": make_password(otp),

            "otp_expiry": (
                timezone.now() + timedelta(minutes=5)
            ).isoformat(),
        }

        cache_key = f"pending_registration:{email}"

        # Store pending registration for 5 minutes.
        cache.set(cache_key, pending_data, timeout=300)

        try:
            send_otp_via_email(email, otp)
        except Exception:
            cache.delete(cache_key)
            return Response(
                {"error": "Unable to send OTP. Please try again."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response(
            {
                "message": "OTP sent successfully.",
                "email": email
            },
            status=status.HTTP_200_OK
        )



from datetime import datetime


class Otpverification(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OtpVerificationSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data["email"].strip().lower()
        entered_otp = serializer.validated_data["otp"]

        cache_key = f"pending_registration:{email}"
        pending = cache.get(cache_key)

        if pending is None:
            return Response(
                {
                    "error": (
                        "Registration expired or not found. "
                        "Please register again."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        expiry = datetime.fromisoformat(pending["otp_expiry"])

        if timezone.now() >= expiry:
            cache.delete(cache_key)
            return Response(
                {"error": "OTP expired. Please register again."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not check_password(entered_otp, pending["otp_hash"]):
            return Response(
                {"error": "Invalid OTP."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            with transaction.atomic():
                # Use the already-hashed password directly.
                # Do NOT call set_password() on this hash.
                user = User(
                    username=pending["username"],
                    email=pending["email"],
                    phone_number=pending["phone_number"],
                    password=pending["password"],
                    is_active=True,
                    user_type="patient",
                )
                user.save()

                UserProfile.objects.create(user=user)

        except IntegrityError:
            # Another request may have registered the email
            # or username after our initial uniqueness check.
            return Response(
                {
                    "error": (
                        "This email or username is already registered. "
                        "Please try logging in."
                    )
                },
                status=status.HTTP_409_CONFLICT
            )

        # Delete pending data only after the database transaction succeeds.
        cache.delete(cache_key)

        return Response(
            {"message": "Registration and email verification successful."},
            status=status.HTTP_201_CREATED
        )




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
        new_password = request.data.get('password')

        # Validate password
        if not new_password or len(new_password) < 8:
            return Response({'error': 'Password must be at least 8 characters long.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.search(r'[A-Z]', new_password):
            return Response({'error': 'Password must contain at least one uppercase letter.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.search(r'\d', new_password):
            return Response({'error': 'Password must contain at least one number.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            return Response({'error': 'Password must contain at least one special character.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user.password = make_password(new_password)
            user.save()
            return Response({'success': True, 'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class ResendOtpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip().lower()

        if not email:
            return Response(
                {"error": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        cache_key = f"pending_registration:{email}"
        pending = cache.get(cache_key)

        if pending is None:
            return Response(
                {
                    "error": (
                        "Registration expired or not found. "
                        "Please register again."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(email__iexact=email).exists():
            cache.delete(cache_key)
            return Response(
                {"error": "An account with this email already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        old_pending = pending.copy()

        otp = f"{secrets.randbelow(1_000_000):06d}"

        pending["otp_hash"] = make_password(otp)
        pending["otp_expiry"] = (
            timezone.now() + timedelta(minutes=5)
        ).isoformat()

        cache.set(cache_key, pending, timeout=300)

        try:
            send_otp_via_email(email, otp)
        except Exception:
            cache.set(cache_key, old_pending, timeout=300)

            return Response(
                {"error": "Unable to send OTP. Please try again."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response(
            {
                "message": "A new OTP has been sent.",
                "email": email
            },
            status=status.HTTP_200_OK
        )

        


                
class UserProfileView(APIView):
    permission_classes = [IsPatient]
    print(permission_classes)

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "UserProfile not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Use a serializer that includes profile details
        serializer = UserProfileDetailSerializer(user_profile)
        return Response(serializer.data)

class EditProfileView(APIView):
    permission_classes = [IsPatient]

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

        # Create a serializer instance with partial updates allowed
        serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)

        # Check if 'profile_pic' is in request.data and handle it properly
        if 'profile_pic' in request.data and request.data['profile_pic'] == '':
            request.data['profile_pic'] = None

        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        print("error", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class Doctors_list(ListAPIView):
    permission_classes = [IsPatient]
    
    serializer_class = DoctorProfileSerializer

    def get_queryset(self):
        queryset = DoctorProfile.objects.filter(is_verified=True)
        search_term = self.request.query_params.get('search', None)
        if search_term:
            queryset = queryset.filter(
                Q(first_name__icontains=search_term) |  
                Q(last_name__icontains=search_term)|  
                Q(specification__icontains=search_term) 
            )
        
        return queryset

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


from datetime import datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListAPIView

class SlotListView(ListAPIView):
    permission_classes = [IsPatient]
    serializer_class = SlotCreateSerializer

    def get_queryset(self):
        doctor_id = self.kwargs.get('doctor_id')
        date_filter = self.request.query_params.get('date', None)
        time_filter = self.request.query_params.get('time', None)

        print(f"Requested doctor ID: {doctor_id}")
        print(f"Date filter: {date_filter}")
        print(f"Time filter: {time_filter}")

        try:
            doctor = DoctorProfile.objects.get(id=doctor_id)
            if doctor.is_verified:
                # Start with all available slots for the doctor
                slots = Slots.objects.filter(doctor=doctor, is_booked=False)

                # Apply date filtering if provided
                if date_filter:
                    try:
                        date_obj = datetime.strptime(date_filter, '%Y-%m-%d').date()
                        slots = slots.filter(date=date_obj)
                    except ValueError:
                        return Slots.objects.none()  # Invalid date format

                # Apply time filtering if provided
                if time_filter:
                    # Assuming `time_filter` is in 'HH:MM AM/PM' format
                    try:
                        time_obj = datetime.strptime(time_filter, '%I:%M %p').time()
                        slots = slots.filter(start_time__time=time_obj)  # Adjust field as necessary
                    except ValueError:
                        return Slots.objects.none()  # Invalid time format

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



def get_idempotency_key(request):
    """The frontend must send the same UUID when retrying the same booking attempt."""
    try:
        return uuid.UUID(request.headers.get("Idempotency-Key", ""))
    except (ValueError, TypeError, AttributeError):
        return None
 
 
def error_response(exc):
    return Response({"error": exc.message, "code": exc.code}, status=exc.status_code)
 
 
def parse_expected_amount(raw):
    if raw in (None, ""):
        return None
    try:
        return Decimal(str(raw))
    except InvalidOperation:
        raise BookingError("expected_amount is invalid.", 400, "invalid_amount")




def find_existing_booking(user, key):
    return Bookings.objects.filter(
        user=user,
        idempotency_key=key,
    ).first()


def release_expired_reservation(booking):
    """
    Call inside transaction.atomic(), after locking the slot
    and booking.

    Only release an expired, unpaid Razorpay reservation.
    """
    if (
        booking.payment_method != "razorpay"
        or booking.status != "pending"
        or not booking.expires_at
        or booking.expires_at > timezone.now()
    ):
        return False

    payment = Transaction.objects.filter(
        booking=booking,
        status="completed",
    ).exists()

    if payment:
        return False

    slot = Slots.objects.select_for_update().get(
        pk=booking.slots_id
    )

    slot.is_booked = False
    slot.save(update_fields=["is_booked"])

    # Transaction.booking uses SET_NULL, so its payment
    # record can remain if the booking is deleted.
    booking.delete()
    return True

        
    



class BookSlotView(APIView):
    """
    Reserves a slot.
      wallet   -> pays immediately; 201 with a pending (paid) booking.
      razorpay -> holds the slot for 15 minutes as 'awaiting_payment' and returns an order.
                  It is NOT an appointment until PaymentCallback/webhook confirms the money.
    Retrying with the same Idempotency-Key always returns the same booking/order.
    """
    permission_classes = [IsPatient]
 
    def post(self, request, doctor_id, slot_id):
        payment_method = request.data.get("payment_method", "razorpay")
        key = get_idempotency_key(request)
 
        if key is None:
            return Response(
                {"error": "A valid UUID Idempotency-Key header is required.", "code": "invalid_key"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if payment_method not in ("wallet", "razorpay"):
            return Response(
                {"error": "payment_method must be wallet or razorpay.", "code": "invalid_method"},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        try:
            expected_amount = parse_expected_amount(request.data.get("expected_amount"))
 
            booking = find_existing_booking(request.user, key)  # fast path for retries
            created = False
            if booking is None:
                booking, created = reserve_slot(
                    request.user, doctor_id, slot_id, payment_method, key, expected_amount
                )
 
            if (
                str(booking.doctor_id) != str(doctor_id)
                or str(booking.slots_id) != str(slot_id)
                or booking.payment_method != payment_method
            ):
                raise BookingError(
                    "Idempotency key reused with different booking details.",
                    409, "idempotency_key_reused",
                )
 
            if booking.payment_method == "wallet":
                return self._wallet_response(booking, created)
            return self._razorpay_response(booking, created)
 
        except BookingError as exc:
            return error_response(exc)
        except Exception:
            logger.exception("Booking creation failed")
            return Response(
                {"error": "Unable to process the booking. Retry with the same Idempotency-Key.",
                 "code": "server_error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
 
    @staticmethod
    def _wallet_response(booking, created):
        if booking.status not in (Bookings.PENDING, Bookings.COMPLETED):
            raise BookingError(
                "Your reservation is no longer active. Please select the slot again.",
                409, "reservation_expired",
            )
        payment = WalletTransaction.objects.filter(booking=booking, status="completed").first()
        return Response({
            "message": "Booking created and wallet payment completed."
                       if created else "This booking was already processed.",
            "already_processed": not created,
            "amount": str(payment.amount) if payment else None,
            "currency": "INR",
            "booking_id": booking.id,
            "wallet_transaction": str(payment) if payment else None,
        }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)
 
    @staticmethod
    def _razorpay_response(booking, created):
        if booking.status in (Bookings.PENDING, Bookings.COMPLETED):
            # already paid and confirmed: nothing to pay again
            return Response(
                {"already_processed": True, "booking_id": booking.id, "status": booking.status},
                status=status.HTTP_200_OK,
            )
 
        try:
            booking, payment = ensure_razorpay_order(booking.pk)
        except BookingError:
            raise
        except Exception:
            logger.exception("Razorpay order creation failed for booking %s", booking.pk)
            return Response(
                {"error": "The payment gateway is unavailable. Retry with the same Idempotency-Key.",
                 "code": "gateway_error"},
                status=status.HTTP_502_BAD_GATEWAY,
            )
 
        expires_in = max(0, int((booking.expires_at - timezone.now()).total_seconds()))
        return Response({
            "already_processed": False,
            "razorpay_order_id": payment.razorpay_order_id,
            "razorpay_key_id": settings.RAZORPAY_KEY_ID,
            "amount": str(payment.amount),
            "amount_paise": to_paise(payment.amount),
            "currency": payment.currency,
            "booking_id": booking.id,
            "expires_in": expires_in,  # seconds; frontend uses this, not its own clock
        }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)
 
 
def _payment_outcome_response(outcome, payment):
    if outcome == "confirmed":
        return Response({"message": "Payment verified successfully."}, status=status.HTTP_200_OK)
    if outcome == "already_confirmed":
        return Response({"message": "Payment was already verified."}, status=status.HTTP_200_OK)
    
    if outcome in ("refund_required", "refunded"):
        refund_status = refund_payment(payment.pk)
        is_refunded = refund_status == "refunded"

        return Response(
            {
                "error": (
                    "This slot was no longer available when your payment arrived. "
                    + (
                        "Your payment has been refunded."
                        if is_refunded
                        else "Your refund is pending confirmation."
                    )
                ),
                "code": "payment_refund",
                "refund_status": refund_status,
            },
            status=status.HTTP_409_CONFLICT,
        )

    if outcome == "not_found":
        return Response({"error": "Transaction not found.", "code": "not_found"},
                        status=status.HTTP_404_NOT_FOUND)
    return Response({"error": "Payment does not match this booking.", "code": "mismatch"},
                    status=status.HTTP_400_BAD_REQUEST)
 
 
class PaymentCallback(APIView):
    """Browser-side confirmation after Razorpay Checkout succeeds. Idempotent."""
    permission_classes = [IsPatient]
 
    def post(self, request):
        payment_id = request.data.get("razorpay_payment_id")
        order_id = request.data.get("razorpay_order_id")
        signature = request.data.get("razorpay_signature")
        booking_id = request.data.get("booking_id")
 
        if not all([payment_id, order_id, signature, booking_id]):
            return Response({"error": "Missing payment verification fields.", "code": "missing_fields"},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            razorpay_client().utility.verify_payment_signature({
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature,
            })
        except SignatureVerificationError:
            return Response({"error": "Payment signature verification failed.", "code": "bad_signature"},
                            status=status.HTTP_400_BAD_REQUEST)
 
        outcome, payment = confirm_razorpay_payment(
            order_id, payment_id, signature, user=request.user, booking_id=booking_id
        )
        return _payment_outcome_response(outcome, payment)
 
 

class RazorpayWebhookView(APIView):
    """
    Handles captured Razorpay payments for appointments and wallet top-ups.

    Configure payment.captured in the Razorpay Dashboard.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        body = request.body.decode("utf-8")
        signature = request.headers.get("X-Razorpay-Signature", "")

        # 1. Verify the webhook signature.
        try:
            razorpay_client().utility.verify_webhook_signature(
                body,
                signature,
                settings.RAZORPAY_WEBHOOK_SECRET,
            )
        except SignatureVerificationError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # 2. Parse the event.
        try:
            event = json.loads(body)
        except (ValueError, TypeError):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # We currently process payment.captured only.
        # Other valid events are acknowledged but not processed here.
        if event.get("event") != "payment.captured":
            return Response(status=status.HTTP_200_OK)

        try:
            entity = event["payload"]["payment"]["entity"]

            order_id = entity.get("order_id")
            payment_id = entity.get("id")

            if not order_id or not payment_id:
                return Response(status=status.HTTP_400_BAD_REQUEST)

            # 3. Route wallet top-ups separately.
            topup_exists = WalletTopUp.objects.filter(
                razorpay_order_id=order_id
            ).exists()

            if topup_exists:
                outcome = confirm_wallet_topup(
                    order_id=order_id,
                    payment_id=payment_id,
                    amount_paise=entity.get("amount"),
                    payment_status=entity.get("status"),
                    payment_currency=entity.get("currency"),
                )

                if outcome not in (
                    "confirmed",
                    "already_confirmed",
                ):
                    logger.error(
                        "Wallet top-up webhook outcome %s for order %s",
                        outcome,
                        order_id,
                    )

                # A valid event was processed or logged for reconciliation.
                return Response(status=status.HTTP_200_OK)

            # 4. Otherwise, handle an appointment payment.
            outcome, payment = confirm_razorpay_payment(
                order_id,
                payment_id,
                amount_paise=entity.get("amount"),
            )

            if outcome == "refund_required":
                refund_payment(payment.pk)

            elif outcome in ("not_found", "mismatch"):
                logger.error(
                    "Appointment webhook outcome %s for order %s",
                    outcome,
                    order_id,
                )

        except (ValueError, KeyError, TypeError):
            logger.exception("Invalid Razorpay webhook payload")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        except Exception:
            logger.exception("Razorpay webhook processing failed")
            # A 500 response allows Razorpay to retry.
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(status=status.HTTP_200_OK)





@api_view(["PATCH"])
@permission_classes([IsAuthenticated, IsPatient])
def cancel_appointment(request, booking_id):
    result = cancel_appointment_service(
        booking_id=booking_id,
        user=request.user,
    )

    if result["result"] == "not_found":
        return Response(
            {"error": "Booking not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    if result["result"] == "already_cancelled":
        return Response(
            {"message": "Appointment is already cancelled."},
            status=status.HTTP_200_OK,
        )

    if result["result"] == "not_eligible":
        return Response(
            {"error": result["message"]},
            status=status.HTTP_409_CONFLICT,
        )

    if result["result"] == "refund_failed":
        return Response(
            {
                "error": result["message"],
                "refund_status": result["refund_status"],
            },
            status=status.HTTP_409_CONFLICT,
        )

    if result["result"] == "payment_pending":
        return Response(
            {
                "error": result["message"],
                "refund_status": result.get("refund_status"),
            },
            status=status.HTTP_202_ACCEPTED,
        )

    if result["result"] == "cancelled":
        return Response(
            {
                "message": "Appointment cancelled successfully.",
                "refund_status": result.get("refund_status"),
            },
            status=status.HTTP_200_OK,
        )

    return Response(
        {"error": "Unable to cancel appointment."},
        status=status.HTTP_400_BAD_REQUEST,
    )



    

        
    
from django.http import JsonResponse, HttpResponseBadRequest
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
import json


@api_view(["PATCH"])
@permission_classes([IsAuthenticated, IsPatient])
def update_status(request, pk):
    if request.data.get("status") != "cancelled":
        return Response(
            {
                "error": (
                    "Only cancellation is supported by this endpoint."
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Call the service directly, not the API view.
    result = cancel_appointment_service(
        booking_id=pk,
        user=request.user,
    )

    if result["result"] == "not_found":
        return Response(
            {"error": "Booking not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    if result["result"] == "already_cancelled":
        return Response(
            {"message": "Appointment is already cancelled."},
            status=status.HTTP_200_OK,
        )

    if result["result"] == "not_eligible":
        return Response(
            {"error": result["message"]},
            status=status.HTTP_409_CONFLICT,
        )

    if result["result"] == "refund_failed":
        return Response(
            {
                "error": result["message"],
                "refund_status": result["refund_status"],
            },
            status=status.HTTP_409_CONFLICT,
        )

    if result["result"] == "payment_pending":
        return Response(
            {
                "error": result["message"],
                "refund_status": result.get("refund_status"),
            },
            status=status.HTTP_202_ACCEPTED,
        )

    if result["result"] == "cancelled":
        return Response(
            {
                "message": "Appointment cancelled successfully.",
                "refund_status": result.get("refund_status"),
            },
            status=status.HTTP_200_OK,
        )

    return Response(
        {"error": "Unable to cancel appointment."},
        status=status.HTTP_400_BAD_REQUEST,
    )

 
 
# --------------------------------------------------------------------------- read
 
class MyAppointments(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer
 
    def get_queryset(self):
        params = self.request.query_params
 
        # THE BUG: this used to be Bookings.objects.filter(user=user), which included unpaid
        # holds. Appointments are only bookings that were actually paid for.
        queryset = (
            Bookings.objects.filter(user=self.request.user, status__in=Bookings.VISIBLE_STATUSES)
            .select_related("user", "doctor", "doctor__user", "slots")
            .prefetch_related("transaction_set", "wallettransaction_set")
        )
 
        search = params.get("search")
        if search:
            queryset = queryset.filter(
                Q(doctor__first_name__icontains=search)
                | Q(doctor__last_name__icontains=search)
                | Q(doctor__user__username__icontains=search)
                | Q(doctor__specification__icontains=search)
            )
 
        start_raw, end_raw = params.get("start_date"), params.get("end_date")
        if start_raw and end_raw:
            start_date, end_date = parse_date(start_raw), parse_date(end_raw)
            if not start_date or not end_date:
                raise ValidationError("Invalid date format. Use YYYY-MM-DD.")
            if start_date > end_date:
                raise ValidationError("Start date must be less than or equal to end date.")
            queryset = queryset.filter(created_at__date__range=(start_date, end_date))
 
        wanted = params.get("status")
        if wanted in Bookings.VISIBLE_STATUSES:
            queryset = queryset.filter(status=wanted)
 
        if (params.get("verified_only") or "").lower() == "true":
            queryset = queryset.filter(doctor__is_verified=True)
 
        return queryset.order_by("-created_at")
 
 
class AppointmentDetailsView(RetrieveAPIView):
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "pk"
 
    def get_queryset(self):
        return (
            Bookings.objects.filter(user=self.request.user, status__in=Bookings.VISIBLE_STATUSES)
            .select_related("user", "doctor", "doctor__user", "slots")
            .prefetch_related("transaction_set", "wallettransaction_set")
        )
 





class WalletDetailView(RetrieveAPIView):
    permission_classes = [IsPatient]
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
    permission_classes = [IsPatient]

    def post(self, request):
        booking_id = request.data.get("booking_id")

        if not booking_id:
            return Response(
                {"error": "booking_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        booking = get_object_or_404(
            Bookings,
            pk=booking_id,
            user=request.user,
            payment_method="wallet",
        )

        wallet_payment = WalletTransaction.objects.filter(
            booking=booking,
            user=request.user,
        ).first()

        if not wallet_payment:
            return Response(
                {"error": "Wallet transaction not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if wallet_payment.status != "completed":
            return Response(
                {"error": "Wallet payment has not been completed."},
                status=status.HTTP_409_CONFLICT,
            )

        return Response({
            "message": "Wallet payment was already processed.",
            "booking_id": booking.id,
            "payment_status": wallet_payment.status,
            "booking_status": booking.status,
        }, status=status.HTTP_200_OK)




from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from Doctors.booking_service import cancel_checkout_reservation



@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPatient])
def cancel_pending_reservation(request, booking_id):
    result = cancel_checkout_reservation(
        booking_id=booking_id,
        user=request.user,
    )

    if result == "not_found":
        return Response(
            {"detail": "Reservation not found."},
            status=404,
        )

    if result == "released":
        return Response({
            "released": True,
            "status": "expired",
            "message": "Reservation released.",
        })

    if result == "paid":
        return Response({
            "released": False,
            "status": "paid",
            "message": (
                "Payment succeeded or the appointment is confirmed."
            ),
        })

    if result == "keep_reserved":
        return Response(
            {
                "released": False,
                "status": "payment_pending",
                "message": (
                    "Payment status is not conclusive. "
                    "Your reservation remains active temporarily."
                ),
            },
            status=202,
        )

    return Response({
        "released": False,
        "status": "already_finished",
        "message": "This reservation is no longer awaiting payment.",
    })



@api_view(["PATCH"])
@permission_classes([IsAuthenticated, IsPatient])
def cancel_wallet_appointment(request, booking_id):
    result = cancel_appointment_service(
        booking_id=booking_id,
        user=request.user,
    )

    if result["result"] == "not_found":
        return Response(
            {"error": "Booking not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    if result["result"] == "already_cancelled":
        return Response(
            {"message": "Appointment is already cancelled."},
            status=status.HTTP_200_OK,
        )

    if result["result"] == "not_eligible":
        return Response(
            {"error": result["message"]},
            status=status.HTTP_409_CONFLICT,
        )

    if result["result"] == "refund_failed":
        return Response(
            {
                "error": result["message"],
                "refund_status": result.get("refund_status"),
            },
            status=status.HTTP_409_CONFLICT,
        )

    if result["result"] == "payment_pending":
        return Response(
            {
                "error": result["message"],
                "refund_status": result.get("refund_status"),
            },
            status=status.HTTP_202_ACCEPTED,
        )

    if result["result"] == "cancelled":
        return Response(
            {
                "message": "Wallet appointment cancelled successfully.",
                "refund_status": result.get("refund_status"),
                "refund_amount": result.get("refund_amount"),
                "payment_method": result.get("payment_method"),
            },
            status=status.HTTP_200_OK,
        )

    return Response(
        {"error": "Unable to cancel wallet appointment."},
        status=status.HTTP_400_BAD_REQUEST,
    )






@api_view(["POST"])
@permission_classes([IsAuthenticated, IsPatient])
def create_wallet_topup(request):
    amount = request.data.get("amount")

    try:
        result = create_wallet_topup_order(
            user=request.user,
            amount=amount,
        )

    except BookingError as exc:
        return Response(
            {"error": exc.message, "code": exc.code},
            status=exc.status_code,
        )

    except Exception:
        logger.exception(
            "Unexpected error creating wallet top-up for user %s",
            request.user.pk,
        )
        return Response(
            {
                "error": "The payment gateway is unavailable. Please retry.",
                "code": "gateway_error",
            },
            status=status.HTTP_502_BAD_GATEWAY,
        )

    return Response(
        {
            "message": "Wallet top-up order created.",
            "topup_id": result["topup_id"],
            "razorpay_order_id": result["order_id"],
            "razorpay_key_id": result["key_id"],
            "amount": result["amount"],
            "amount_paise": result["amount_paise"],
            "currency": result["currency"],
        },
        status=status.HTTP_201_CREATED,
    )



class WalletTopUpCallbackView(APIView):
    """Verify a Razorpay Checkout payment for a wallet top-up."""

    permission_classes = [IsAuthenticated, IsPatient]

    def post(self, request):
        order_id = request.data.get("razorpay_order_id")
        payment_id = request.data.get("razorpay_payment_id")
        signature = request.data.get("razorpay_signature")

        if not all([order_id, payment_id, signature]):
            return Response(
                {
                    "error": "Missing payment verification fields.",
                    "code": "missing_fields",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = razorpay_client()

        # 1. Verify the signature from Razorpay Checkout.
        try:
            client.utility.verify_payment_signature({
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature,
            })
        except SignatureVerificationError:
            return Response(
                {
                    "error": "Payment signature verification failed.",
                    "code": "bad_signature",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2. Fetch payment details directly from Razorpay.
        try:
            payment = client.payment.fetch(payment_id)
        except Exception:
            logger.exception(
                "Unable to fetch Razorpay payment %s",
                payment_id,
            )
            return Response(
                {
                    "error": "Unable to verify payment status. Please retry.",
                    "code": "payment_verification_unavailable",
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        # 3. Verify that this payment belongs to the submitted order.
        if payment.get("order_id") != order_id:
            return Response(
                {
                    "error": "Payment does not match the order.",
                    "code": "payment_mismatch",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 4. Credit only after Razorpay confirms capture.
        outcome = confirm_wallet_topup(
            order_id=order_id,
            payment_id=payment_id,
            amount_paise=payment.get("amount"),
            payment_status=payment.get("status"),
            payment_currency=payment.get("currency"),
            user=request.user,
        )

        if outcome in ("confirmed", "already_confirmed"):
            return Response(
                {
                    "message": (
                        "Wallet topped up successfully."
                        if outcome == "confirmed"
                        else "This top-up was already processed."
                    ),
                    "status": "SUCCESS",
                    "already_processed": outcome == "already_confirmed",
                },
                status=status.HTTP_200_OK,
            )

        if outcome == "payment_not_captured":
            return Response(
                {
                    "error": "Payment has not been captured yet.",
                    "code": outcome,
                },
                status=status.HTTP_409_CONFLICT,
            )

        if outcome == "not_found":
            return Response(
                {"error": "Top-up not found.", "code": outcome},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {
                "error": "Payment could not be matched to this top-up.",
                "code": outcome,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
