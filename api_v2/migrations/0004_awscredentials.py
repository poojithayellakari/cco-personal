# Generated by Django 4.2 on 2023-11-29 05:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v2', '0003_alter_custom_user_password'),
    ]

    operations = [
        migrations.CreateModel(
            name='AWSCredentials',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('access_key', models.CharField(max_length=20)),
                ('secret_key', models.CharField(max_length=40)),
            ],
        ),
    ]
