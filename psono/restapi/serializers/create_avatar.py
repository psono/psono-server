from django.conf import settings
from PIL import Image
import io
import base64
from rest_framework import serializers, exceptions
from restapi.utils.images import crop_to_aspect


class CreateAvatarSerializer(serializers.Serializer):
    data_base64 = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:
        data_base64 = attrs.get("data_base64", "")
        max_size_bytes = settings.AVATAR_MAX_SIZE_KB * 1024
        max_base64_size = ((max_size_bytes + 2) // 3) * 4

        if len(data_base64) > max_base64_size:
            raise exceptions.ValidationError("SIZE_EXCEEDED")

        try:
            img_data = base64.b64decode(data_base64, validate=True)
        except (base64.binascii.Error, ValueError):
            raise exceptions.ValidationError("INVALID_BASE64")

        if len(img_data) > max_size_bytes:
            raise exceptions.ValidationError("SIZE_EXCEEDED")

        file = io.BytesIO(img_data)
        mime_type = None

        try:
            image = Image.open(file, formats=["JPEG", "PNG"])
            if image.width * image.height > settings.AVATAR_MAX_PIXELS:
                raise exceptions.ValidationError("DIMENSIONS_EXCEEDED")

            # Verify integrity before decoding the pixel data.
            image.verify()  # Verify the image (checks integrity but not decoded)
            file.seek(0)
            image = Image.open(file, formats=["JPEG", "PNG"])
            image.load()
            format = image.format
            mime_type = Image.MIME.get(format)
        except exceptions.ValidationError:
            raise
        except Exception:
            raise exceptions.ValidationError("DATA_NO_IMAGE")

        # Check image dimensions
        if (
            image.width != settings.AVATAR_DIMENSION_X
            or image.height != settings.AVATAR_DIMENSION_Y
        ):
            image = crop_to_aspect(
                image,
                target_width=settings.AVATAR_DIMENSION_X,
                target_height=settings.AVATAR_DIMENSION_Y,
            )

        # Cleanse the image by saving it to a buffer
        buffer = io.BytesIO()
        image.save(buffer, format=format)

        # Update the attrs dictionary
        attrs["data"] = buffer.getvalue()
        attrs["mime_type"] = mime_type

        return attrs
