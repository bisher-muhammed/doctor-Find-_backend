from django.db import migrations, models
import django.utils.timezone

class Migration(migrations.Migration):

    dependencies = [
        ('Chat', '0004_remove_chatroom_participants_chatroom_doctor_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='chatmessage',
            name='date',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
