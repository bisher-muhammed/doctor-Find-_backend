from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics, permissions, status
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from Users.models import MyUser, UserProfile
from Users.serializers import TransactionSerializer, UserProfileDetailSerializer, UserProfileSerializer, WalletTransactionSerializer
from Users.utils import generate_pdf,send_notification_user
from Doctors.models import DoctorProfile, Transaction, WalletTransaction
from Doctors.serializers import DocumentSerializer,DoctorProfileSerializer
from django.contrib import messages
from Doctors.models import Document
from rest_framework.generics import ListAPIView
from django.db.models import Q, Sum
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from datetime import datetime
from Users.permissions import IsAdmin
import io

from rest_framework_simplejwt.authentication import JWTAuthentication

from Users.serializers import BookingSerializer
from Doctors.models import Bookings


class AdminLogin(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        required_fields = ['email', 'password']

        if not all(field in data for field in required_fields):
            return Response({'detail': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = data.get('email')
            print('email',email)
            password = data.get('password')
            print('password:',password)

            if not email or not password:
                return Response({'detail': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(username=email, password=password)
            print('user:',user)

            if user is not None and user.is_superuser:
                refresh = RefreshToken.for_user(user)
                refresh['username'] = str(user.username)
                access_token = refresh.access_token
                refresh_token = str(refresh)
                print("user logined")

                content = {
                    'access_token': str(access_token),
                    'refresh_token': refresh_token,
                    'isAdmin': user.is_superuser,
                }
                return Response(content, status=status.HTTP_200_OK)
            

            elif user is not None and not user.is_superuser:
                return Response({'detail': 'This account is not a Superuser account'}, status=status.HTTP_401_UNAUTHORIZED)

            else:
                return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


import logging
logger = logging.getLogger(__name__)


class FetchDocuments(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = DocumentSerializer

    def get_queryset(self):
        try:
            documents = Document.objects.select_related('doctor').all()
            logger.debug(f"Documents fetched: {documents}")
            return documents
        except Exception as e:
            logger.error(f"Error fetching documents: {str(e)}", exc_info=True)
            raise

    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching documents: {str(e)}", exc_info=True)
            return Response({'detail': 'An error occurred while fetching documents.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)










import logging

logger = logging.getLogger(__name__)

class VerifyDocuments(generics.UpdateAPIView):
    permission_classes = [IsAdmin]
    """
    View to verify doctor profiles.
    """

    def get_object(self):
        raise NotImplementedError("This view does not handle single object retrieval.")

    def post(self, request, *args, **kwargs):
        logger.info("Received request to verify doctor profiles.")
        logger.info(f"User is superuser: {request.user.is_superuser}")

        if not request.user.is_superuser:
            logger.warning("Unauthorized attempt to verify documents by non-superuser.")
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        
        # Directly get data from the request
        document_ids = request.data.get('document_ids', [])
        doctor_id = request.data.get('doctor_id')

        # Validate the input
        if not document_ids or not doctor_id:
            return Response({'detail': 'Both document_ids and doctor_id are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the provided doctor ID exists in the DoctorProfile model
        if not DoctorProfile.objects.filter(id=doctor_id).exists():
            return Response({'doctor_id': 'Doctor does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if all document IDs exist and belong to the given doctor
        invalid_documents = [
            doc_id for doc_id in document_ids
            if not Document.objects.filter(id=doc_id, doctor_id=doctor_id).exists()
        ]

        if invalid_documents:
            return Response({
                'document_ids': f"The following document IDs are invalid or do not belong to the specified doctor: {invalid_documents}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update the `is_verified` field in DoctorProfile
        updated_count = DoctorProfile.objects.filter(id=doctor_id).update(is_verified=True)
        logger.info(f"Doctor profiles updated successfully: {updated_count}")

        return Response({'message': f'Doctor profile with ID {doctor_id} has been marked as verified.'}, status=status.HTTP_200_OK)
    


class DoctorsList(ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = DoctorProfileSerializer

    def get_queryset(self):
    # Fetching all verified doctors of user type 'doctor'
        return DoctorProfile.objects.filter(user__user_type='doctor', is_verified=True)

    



class DoctorStatus(generics.UpdateAPIView):
    permission_classes = [IsAdmin]
    def post(self, request, pk):
        try:
            # Retrieve the doctor profile by primary key
            doctor = DoctorProfile.objects.get(pk=pk)
            # Toggle the is_active status
            doctor.user.is_active = not doctor.user.is_active
            doctor.user.save()  # Save the changes to the user object
            print(doctor.user.is_active)
            
            # Prepare a message based on the new status
            status_message = "Active" if doctor.user.is_active else "Blocked"
            return Response({'is_active': doctor.user.is_active, 'status': status_message}, status=status.HTTP_200_OK)
        except DoctorProfile.DoesNotExist:
            return Response({'error': 'Doctor not found.'}, status=status.HTTP_404_NOT_FOUND)



class UsersList(ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = UserProfileDetailSerializer

    def get_queryset(self):
        # Fetching all users where the user type is 'patient'
        return UserProfile.objects.filter(user__user_type='patient')

    



class UserStatus(generics.UpdateAPIView):
    permission_classes = [IsAdmin]
    def post(self, request, pk):
        try:
            # Retrieve the doctor profile by primary key
            user = UserProfile.objects.get(pk=pk)
            # Toggle the is_active status
            user.user.is_active = not user.user.is_active
            user.user.save()  # Save the changes to the user object
            print(user.user.is_active)
            
            # Prepare a message based on the new status
            status_message = "Active" if user.user.is_active else "Blocked"
            return Response({'is_active': user.user.is_active, 'status': status_message}, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({'error': 'Doctor not found.'}, status=status.HTTP_404_NOT_FOUND)
        


from django.db.models import Sum
from django.utils import timezone
from django.db.models.functions import TruncMonth, TruncYear


class Total_Revenue(generics.RetrieveAPIView):
    permission_classes = [IsAdmin]

    def get(self, request, *args, **kwargs):
        # Get the current date and time
        now = timezone.now()
        current_year = now.year

        # YEARLY REVENUE
        transactions_yearly = Transaction.objects.filter(status='completed').annotate(
            year=TruncYear('created_at')
        ).values('year').annotate(
            total_revenue=Sum('amount')  # Use 'amount' field from Transaction
        ).order_by('year')

        wallet_yearly = WalletTransaction.objects.filter(status='completed').annotate(
            year=TruncYear('created_at')
        ).values('year').annotate(
            total_revenue=Sum('amount')  # Use 'amount' field from WalletTransaction
        ).order_by('year')

        # Combine yearly transaction and wallet transaction totals
        yearly_revenue = {}
        for item in transactions_yearly:
            year = item['year'].year
            yearly_revenue[year] = yearly_revenue.get(year, 0) + item['total_revenue']
        for item in wallet_yearly:
            year = item['year'].year
            yearly_revenue[year] = yearly_revenue.get(year, 0) + item['total_revenue']

        # MONTHLY REVENUE (Current year)
        transactions_monthly = Transaction.objects.filter(
            status='completed', created_at__year=current_year
        ).annotate(month=TruncMonth('created_at')).values('month').annotate(
            total_revenue=Sum('amount')  # Use 'amount' field
        ).order_by('month')

        wallet_monthly = WalletTransaction.objects.filter(
            status='completed', created_at__year=current_year
        ).annotate(month=TruncMonth('created_at')).values('month').annotate(
            total_revenue=Sum('amount')  # Use 'amount' field
        ).order_by('month')

        # Combine monthly transaction and wallet transaction totals
        monthly_revenue = {}
        for item in transactions_monthly:
            month = item['month'].strftime('%Y-%m')
            monthly_revenue[month] = monthly_revenue.get(month, 0) + item['total_revenue']
        for item in wallet_monthly:
            month = item['month'].strftime('%Y-%m')
            monthly_revenue[month] = monthly_revenue.get(month, 0) + item['total_revenue']

        # Revenue by specialty
        revenue_by_specialty = (
            Transaction.objects.filter(status='completed')
            .values('booking__doctor__specification')
            .annotate(total_revenue=Sum('amount'))  # Use 'amount' field
        )

        wallet_revenue_by_specialty = (
            WalletTransaction.objects.filter(status='completed')
            .values('booking__doctor__specification')
            .annotate(total_revenue=Sum('amount'))  # Use 'amount' field
        )

        # Combine both revenue_by_specialty results into a single dictionary
        combined_revenue_by_specialties = {}

        # Add revenue from Transaction
        for item in revenue_by_specialty:
            spec = item['booking__doctor__specification']
            total_revenue = item['total_revenue']
            combined_revenue_by_specialties[spec] = combined_revenue_by_specialties.get(spec, 0) + total_revenue

        # Add revenue from WalletTransaction
        for item in wallet_revenue_by_specialty:
            spec = item['booking__doctor__specification']
            total_revenue = item['total_revenue']
            combined_revenue_by_specialties[spec] = combined_revenue_by_specialties.get(spec, 0) + total_revenue

        # Prepare response
        return Response({
            "yearly_revenue": yearly_revenue,
            "monthly_revenue": monthly_revenue,
            "revenue_by_specialties": combined_revenue_by_specialties
        })


class TotalRevenueAndCounts(generics.RetrieveAPIView):
    permission_classes = [IsAdmin]

    def get(self, request, *args, **kwargs):
        # Get the total revenue from completed transactions
        total_transaction_revenue = Transaction.objects.filter(status='completed').aggregate(
            total_revenue=Sum('amount')  # Use 'amount' field
        )['total_revenue'] or 0

        total_wallet_revenue = WalletTransaction.objects.filter(status='completed').aggregate(
            total_revenue=Sum('amount')  # Use 'amount' field
        )['total_revenue'] or 0

        # Combine total revenues
        total_revenue = total_transaction_revenue + total_wallet_revenue

        # Count of all doctors
        doctor_count = MyUser.objects.filter(user_type='doctor').count()

        # Count of all patients
        patient_count = MyUser.objects.filter(user_type='patient').count()

        # Prepare the response
        return Response({
            "total_revenue": total_revenue,
            "doctor_count": doctor_count,
            "patient_count": patient_count
        })


class SalesReportView(APIView):
    permission_classes = [IsAdmin]
    
    def get(self, request, *args, **kwargs):
        # Fetch the date from query parameters (if provided)
        end_date = request.query_params.get('date', None)
        print(f"Requested date: {end_date}")

        # Base query: Get all completed transactions and wallet transactions
        transactions = Transaction.objects.filter(status='completed')
        print(f"Initial transactions: {transactions}")
        
        wallet_transactions = WalletTransaction.objects.filter(status='completed')
        print(f"Initial wallet transactions: {wallet_transactions}")

        # If an end date is provided, filter the transactions and wallet transactions till that date
        if end_date:
            try:
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                transactions = transactions.filter(created_at__date=end_date_obj)
                print(f"Filtered transactions: {transactions}")
                
                wallet_transactions = wallet_transactions.filter(created_at__date=end_date_obj)
                print(f"Filtered wallet transactions: {wallet_transactions}")
            except ValueError:
                return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)

        # Calculate the total amount from transactions and wallet transactions
        total_transaction_amount = transactions.aggregate(total_amount=Sum('amount'))['total_amount'] or 0
        total_wallet_transaction_amount = wallet_transactions.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

        print(f"Total transaction amount: {total_transaction_amount}")
        print(f"Total wallet transaction amount: {total_wallet_transaction_amount}")

        # Calculate the combined total amount
        total_amount = total_transaction_amount + total_wallet_transaction_amount
        print(f"Combined total amount: {total_amount}")

        # Serialize the transactions and wallet transactions
        transaction_serializer = TransactionSerializer(transactions, many=True)
        wallet_transaction_serializer = WalletTransactionSerializer(wallet_transactions, many=True)

        # Prepare the response data
        response_data = {
            'transactions': transaction_serializer.data,
            'wallet_transactions': wallet_transaction_serializer.data,
            'total_amount': total_amount
        }

        return Response(response_data, status=status.HTTP_200_OK)