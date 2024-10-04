# Users/migrations/0003_auto_20240806_1054.py
from django.db import migrations, models
from django.utils import timezone

def set_default_last_login(apps, schema_editor):
    MyUser = apps.get_model('Users', 'MyUser')
    MyUser.objects.filter(last_login__isnull=True).update(last_login=timezone.now())

class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0002_userprofile'),
    ]

    operations = [
        migrations.AddField(
            model_name='myuser',
            name='date_joined',
            field=models.DateTimeField(auto_now_add=True, default=timezone.now, verbose_name='date joined'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='myuser',
            name='otp',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.RunPython(set_default_last_login),
        migrations.AlterField(
            model_name='myuser',
            name='last_login',
            field=models.DateTimeField(auto_now_add=True, verbose_name='last login'),
        ),
    ]

