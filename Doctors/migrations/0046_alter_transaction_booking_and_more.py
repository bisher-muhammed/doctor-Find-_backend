# Generated by Django 4.2.5 on 2024-10-17 08:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0045_transaction_amount_wallettransaction_amount'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='booking',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='Doctors.bookings'),
        ),
        migrations.AlterField(
            model_name='wallettransaction',
            name='booking',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='Doctors.bookings'),
        ),
    ]
