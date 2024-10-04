# Generated by Django 4.2.5 on 2024-08-31 06:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0032_alter_bookings_slot'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='bookings',
            name='slot',
        ),
        migrations.AddField(
            model_name='bookings',
            name='slots',
            field=models.OneToOneField(default=0, on_delete=django.db.models.deletion.CASCADE, related_name='bookings', to='Doctors.slots'),
            preserve_default=False,
        ),
    ]
