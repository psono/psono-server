from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Key_Storage(models.Model):
    create_date = models.DateTimeField(auto_now_add=True)
    write_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    data = models.BinaryField()