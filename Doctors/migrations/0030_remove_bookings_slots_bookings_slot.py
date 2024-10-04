# Generated by Django 4.2.5 on 2024-08-31 05:34

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0029_alter_doctorprofile_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='bookings',
            name='slots',
        ),
        migrations.AddField(
            model_name='bookings',
            name='slot',
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='bookings',
                to='Doctors.slots'
            ),
        ),
    ]
