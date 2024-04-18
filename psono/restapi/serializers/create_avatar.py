from django.conf import settings
from PIL import Image
import io
import base64
from rest_framework import serializers, exceptions


class CreateAvatarSerializer(serializers.Serializer):
    data_base64 = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:
        data_base64 = attrs.get('data_base64', '')

        try:
            img_data = base64.b64decode(data_base64, validate=True)
        except (base64.binascii.Error, ValueError):
            raise exceptions.ValidationError('INVALID_BASE64')

        file = io.BytesIO(img_data)
        mime_type = None

        try:
            # Load the image and verify it's not corrupted
            image = Image.open(file)
            image.verify()  # Verify the image (checks integrity but not decoded)
            file.seek(0)
            image = Image.open(file)
            image.load()
            mime_type = Image.MIME.get(image.format)
        except Exception as exc:
            raise exceptions.ValidationError('DATA_NO_IMAGE')

        # Check image dimensions
        if image.width != settings.AVATAR_DIMENSION_Y or image.height != settings.AVATAR_DIMENSION_Y:
            raise exceptions.ValidationError("INVALID_IMAGE_DIMENSIONS")

        # Calculate the size of image data in bytes to check against the 100KB limit
        if len(img_data) > settings.AVATAR_MAX_SIZE_KB * 1024:
            raise exceptions.ValidationError('SIZE_EXCEEDED')

        # Cleanse the image by saving it to a buffer
        buffer = io.BytesIO()
        image.save(buffer, format=image.format)

        # Update the attrs dictionary
        attrs['data'] = buffer.getvalue()
        attrs['mime_type'] = mime_type

        return attrs