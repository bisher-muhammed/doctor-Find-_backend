# Generated by Django 4.2.5 on 2024-09-02 13:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Chat', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chatroom',
            name='name',
        ),
    ]