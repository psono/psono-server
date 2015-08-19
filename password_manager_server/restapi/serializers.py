from django.contrib.auth.models import User, Group

from models import Key_Storage
from rest_framework import serializers


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('url', 'username', 'email')

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ('url', 'name')

class KeyStorageSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Key_Storage
        fields = ('data', )



