# Generated by Django 4.2.5 on 2024-08-31 05:24

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('Doctors', '0028_alter_bookings_slots'),
    ]

    operations = [
        migrations.AlterField(
            model_name='doctorprofile',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='doctorprofile', to=settings.AUTH_USER_MODEL),
        ),
    ]
