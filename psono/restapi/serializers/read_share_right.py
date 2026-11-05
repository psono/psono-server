from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework import serializers, exceptions

from ..models import User_Share_Right


class ReadShareRightSerializer(serializers.Serializer):
    def validate(self, attrs: dict) -> dict:
        user_share_right_id = (
            self.context["request"]
            .parser_context["kwargs"]
            .get("user_share_right_id", False)
        )

        if not user_share_right_id:
            msg = "USER_SHARE_RIGHT_ID_NOT_PROVIDED"
            raise exceptions.ValidationError(msg)

        try:
            share_right = User_Share_Right.objects.get(pk=user_share_right_id)
        except ValidationError:
            msg = "USER_SHARE_RIGHT_ID_MALFORMED"
            raise exceptions.ValidationError(msg)
        except User_Share_Right.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        user = self.context["request"].user
        if share_right.creator_id != user.id and share_right.user_id != user.id:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if (
            share_right.expiration_date
            and share_right.expiration_date <= timezone.now()
        ):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["share_right"] = share_right

        return attrs
