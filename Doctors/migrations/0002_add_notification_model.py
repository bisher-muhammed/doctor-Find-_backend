from django.db import migrations, models
import django.db.models.deletion
from Users.models import MyUser

class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0001_initial'), # replace with the last migration
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('recipient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Users.myuser')),
            ],
        ),
    ]

