from django.urls import path
from .views import *
from Adminapp.views import VerifyDocuments



urlpatterns = [

    path('admin/login/',AdminLogin.as_view(),name='admin_login'),
    path('admin/fetch_documents/',FetchDocuments.as_view(),name='fetch_documents'),
    # In urls.py
    path('admin/verify_documents/', VerifyDocuments.as_view(), name='verify_documents'),
    path('admin/doctors_list/', DoctorsList.as_view(),name = 'doctors_list'),
    path('admin/doctors/<int:pk>/toggle/', DoctorStatus.as_view(), name='doctor_status'),
    path('admin/users/<int:pk>/toggle/',UserStatus.as_view(), name='user_status'),
    path('admin/users_list/', UsersList.as_view(),name = 'users_list'),
    path('admin/revenue/',Total_Revenue.as_view(),name='revienue_list'),
    path('admin/total-revenue-and-counts/', TotalRevenueAndCounts.as_view(), name='total-revenue-and-counts'),
    path('admin/sales_report/',SalesReportView.as_view(),name='sales_report')


    

]
