# Generated by Django 4.2.5 on 2024-10-07 11:59

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0039_doctorprofile_notifications'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='doctorprofile',
            name='notifications',
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to='Doctors.doctorprofile')),
            ],
        ),
    ]
