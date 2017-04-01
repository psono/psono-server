from django.db import models
from django.db.models import Lookup


class LtreeField(models.CharField):
    description = 'ltree (up to %(max_length)s)'

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 256
        super(LtreeField, self).__init__(*args, **kwargs)

    def db_type(self, connection):
        return 'ltree'

    def deconstruct(self):
        name, path, args, kwargs = super(LtreeField, self).deconstruct()
        del kwargs['max_length']
        return name, path, args, kwargs


class AncestorOrEqual(Lookup):
    lookup_name = 'aore'

    def as_sql(self, qn, connection):
        lhs, lhs_params = self.process_lhs(qn, connection)
        rhs, rhs_params = self.process_rhs(qn, connection)
        params = lhs_params + rhs_params
        return '%s @> %s' % (lhs, rhs), params

LtreeField.register_lookup(AncestorOrEqual)


class DescendantOrEqual(Lookup):
    lookup_name = 'dore'

    def as_sql(self, qn, connection):
        lhs, lhs_params = self.process_lhs(qn, connection)
        rhs, rhs_params = self.process_rhs(qn, connection)
        params = lhs_params + rhs_params
        return '%s <@ %s' % (lhs, rhs), params

LtreeField.register_lookup(DescendantOrEqual)


class Match(Lookup):
    lookup_name = 'match'

    def as_sql(self, qn, connection):
        lhs, lhs_params = self.process_lhs(qn, connection)
        rhs, rhs_params = self.process_rhs(qn, connection)
        params = lhs_params + rhs_params
        return '%s ~ %s' % (lhs, rhs), params

LtreeField.register_lookup(Match)
