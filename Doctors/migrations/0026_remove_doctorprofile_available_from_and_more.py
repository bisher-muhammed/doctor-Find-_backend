# Generated by Django 4.2.5 on 2024-08-31 04:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0025_alter_doctorprofile_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='doctorprofile',
            name='available_from',
        ),
        migrations.RemoveField(
            model_name='doctorprofile',
            name='available_to',
        ),
    ]