from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    """
    Custom permission class to allow only admin users.
    """
    def has_permission(self, request, view):
        print(f"Checking admin permissions for user: {request.user}")  # Print current user
        return request.user.is_authenticated  # Allow authenticated users

    def has_object_permission(self, request, view, obj):
        is_admin = request.user.is_superuser  
        print(f"User: {request.user}, Is Admin: {is_admin}")  
        return is_admin  


class IsDoctor(permissions.BasePermission):
    """
    Custom permission class to allow only doctor users.
    """
    def has_permission(self, request, view):
        print(f"Checking doctor permissions for user: {request.user}")  # Print current user
        return request.user.is_authenticated  # Allow authenticated users

    def has_object_permission(self, request, view, obj):
        is_doctor = request.user.user_type == "doctor"  # Check if the user is a doctor
        print(f"User: {request.user}, Is Doctor: {is_doctor}")  # Print doctor status
        return is_doctor  # Allow only doctors


class IsPatient(permissions.BasePermission):
    """
    Custom permission class to allow only patient users.
    """
    def has_permission(self, request, view):
        print(f"Checking patient permissions for user: {request.user}")  # Print current user
        return request.user.is_authenticated  # Allow authenticated users

    def has_object_permission(self, request, view, obj):
        is_patient = request.user.user_type == "patient"  # Check if the user is a patient
        print(f"User: {request.user}, Is Patient: {is_patient}")  # Print patient status
        return is_patient  # Allow only patients
