# utils.py

from django.core.mail import send_mail
from django.conf import settings 
import random 
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth import get_user_model



User = get_user_model()

def send_otp_via_email(email, otp):
    subject = "Welcome to Find Doctor! - User Verification Mail"
    context = {'otp': otp}
    html_content = render_to_string('email.html', context)
    text_content = strip_tags(html_content)
    email_from = settings.EMAIL_HOST_USER
    try:
        msg = EmailMultiAlternatives(subject, text_content, email_from, [email])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        user_obj = User.objects.get(email=email)
        user_obj.otp = otp
        user_obj.save()
        print(f"OTP sent successfully to {email}")
        print(otp)
    except Exception as e:
        print(f"Error sending OTP to {email}: {e}")

# def send_approval(email):
#     subject = "Find Doctor! Request Approved"
#     html_content = render_to_string('doctor_approval.html')
#     text_content = strip_tags(html_content)
#     email_from = settings.EMAIL_HOST_USER
#     try:
#         msg = EmailMultiAlternatives(subject, text_content, email_from, [email])
#         msg.attach_alternative(html_content, "text/html")
#         msg.send()
#         print(f"Approval sent successfully to {email}")
#     except Exception as e:
#         print(f"Error sending approval to {email}: {e}")



from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io



def generate_pdf(profile):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # Example content, customize as needed
    p.drawString(100, 750, f"Doctor Profile - {profile.user.username}")
    p.drawString(100, 725, f"Full Name: {profile.first_name} {profile.last_name}")
    p.drawString(100, 700, f"Specification: {profile.specification}")
    p.drawString(100, 675, f"Experience: {profile.experience} years")
    
    p.showPage()
    p.save()

    buffer.seek(0)
    return buffer.getvalue()



from django.contrib import messages


def send_notification_user(request, user):
    messages.add_message(request, messages.SUCCESS, 'Your profile has been verified. Please review it.')



from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings

def send_verification(email, doctor_name, start_time, end_time, duration, date, transaction):
    subject = "Your Slot Booking is Confirmed!"
    
    # Prepare the context for the email template
    context = {
        'doctor_name': doctor_name,
        'start_time': start_time.strftime('%H:%M %p'),  # Format time as HH:MM AM/PM
        'end_time': end_time.strftime('%H:%M %p'),      # Format time as HH:MM AM/PM
        'duration': duration,
        'date': date.strftime('%Y-%m-%d'),  # Format date as YYYY-MM-DD
        'transaction': transaction  # Pass the transaction object for other details
    }

    # Render the email content
    html_content = render_to_string('Slot_approval.html', context)
    text_content = strip_tags(html_content)
    email_from = settings.EMAIL_HOST_USER
    
    try:
        # Send the email
        msg = EmailMultiAlternatives(subject, text_content, email_from, [email])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        print(f"Approval sent successfully to {email}")
    except Exception as e:
        print(f"Error sending approval to {email}: {e}")
