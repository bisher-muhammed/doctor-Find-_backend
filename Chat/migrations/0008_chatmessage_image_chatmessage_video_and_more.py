# Generated by Django 4.2.5 on 2024-09-06 03:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Chat', '0007_chatmessage_doctor'),
    ]

    operations = [
        migrations.AddField(
            model_name='chatmessage',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to='media/doctor/chat_images/'),
        ),
        migrations.AddField(
            model_name='chatmessage',
            name='video',
            field=models.FileField(blank=True, null=True, upload_to='media/doctor/chat_videos/'),
        ),
        migrations.AddField(
            model_name='chatmessage',
            name='voice_message',
            field=models.FileField(blank=True, null=True, upload_to='media/doctor/chat_voice_messages/'),
        ),
    ]
