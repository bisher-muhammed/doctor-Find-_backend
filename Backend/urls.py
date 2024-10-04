# Backend/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView, TokenBlacklistView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/chats/', include('Chat.urls')), 
    path('api/users/', include('Users.urls')),  # Ensure the correct path
    path('api/admin/',include('Adminapp.urls')),
    path('api/doctors/',include('Doctors.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
