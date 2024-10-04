from django.db import migrations, models
import django.utils.timezone  # Import timezone utility for default

class Migration(migrations.Migration):

    dependencies = [
        ('Doctors', '0014_remove_document_is_verified_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='slots',
            name='start_date',
            field=models.DateTimeField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
