# Generated by Django 4.2.5 on 2024-08-24 06:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0017_slots_start_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='slots',
            name='end_date',
            field=models.DateField(),
        ),
    ]