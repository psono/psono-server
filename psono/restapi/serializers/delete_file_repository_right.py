from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import File_Repository_Right

class DeleteFileRepositoryRightSerializer(serializers.Serializer):

    file_repository_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_repository_right_id = attrs.get('file_repository_right_id')

        try:
            file_repository_right = File_Repository_Right.objects.get(pk=file_repository_right_id)
        except File_Repository_Right.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        if file_repository_right.user != self.context['request'].user:
            # Its not his own file repository right (leave group functionality) check if the user has the necessary access
            # privileges for this file repository
            try:
                File_Repository_Right.objects.get(group_id=file_repository_right.group_id, user=self.context['request'].user,
                                                  group_admin=True, accepted=True)

            except File_Repository_Right.DoesNotExist:
                msg = _("NO_PERMISSION_OR_NOT_EXIST")
                raise exceptions.ValidationError(msg)

        attrs['file_repository_right'] = file_repository_right

        return attrs