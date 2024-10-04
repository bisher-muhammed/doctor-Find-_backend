# Generated by Django 4.2.5 on 2024-09-04 14:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0035_remove_transaction_razorpay_payment_id_and_more'),
        ('Chat', '0005_chatmessage_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='chatroom',
            name='doctor',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='doctor_rooms', to='Doctors.doctorprofile'),
        ),
    ]