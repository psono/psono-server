from rest_framework import serializers, exceptions
from restapi.models import Group

class ReadSessionSerializer(serializers.Serializer):


    def validate(self, attrs: dict) -> dict:
        group_id = self.context['request'].parser_context['kwargs'].get('group_id', False)

        if group_id:
            try:
                Group.objects.get(pk=group_id)
            except Group.DoesNotExist:
                field = 'group_id'
                msg = 'NO_PERMISSION_OR_NOT_EXIST'
                raise exceptions.ValidationError({field: msg})

        page = self.context['request'].query_params.get('page', False)
        if page and not page.isdigit():
            field = 'page'
            msg = 'ERROR_NO_VALID_INTEGER'
            raise exceptions.ValidationError({field: msg})
        if page and int(page) < 0:
            field = 'page'
            msg = 'ERROR_VALUE_TOO_SMALL'
            raise exceptions.ValidationError({field: msg})

        page_size = self.context['request'].query_params.get('page_size', False)
        if page_size and not page_size.isdigit():
            field = 'page_size'
            msg = 'ERROR_NO_VALID_INTEGER'
            raise exceptions.ValidationError({field: msg})
        if page_size and int(page_size) < 1:
            field = 'page_size'
            msg = 'ERROR_VALUE_TOO_SMALL'
            raise exceptions.ValidationError({field: msg})

        ordering = self.context['request'].query_params.get('ordering', '-create_date')
        search = self.context['request'].query_params.get('search', False)

        attrs['page'] = int(page) + 1
        attrs['page_size'] = int(page_size)
        attrs['ordering'] = ordering
        attrs['search'] = search

        return attrs