# Generated by Django 5.2 on 2025-05-23 21:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='securityevent',
            name='event_id',
            field=models.BigIntegerField(),
        ),
    ]
