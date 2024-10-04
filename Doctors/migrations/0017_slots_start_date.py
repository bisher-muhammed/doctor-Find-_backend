# Generated by Django 4.2.5 on 2024-08-24 04:25

from django.db import migrations, models
from django.utils import timezone


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0016_remove_slots_start_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='slots',
            name='start_date',
            field=models.DateField(default=timezone.now().date()),
            preserve_default=False,
        ),
    ]
