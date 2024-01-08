from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

class Custom_user(models.Model):
    email=models.CharField(max_length=200,unique=True)
    password=models.CharField(max_length=200)

class AWSCredentials(models.Model):
    access_key = models.CharField(max_length=20)
    secret_key = models.CharField(max_length=40)