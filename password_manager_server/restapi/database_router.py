from django.conf import settings

class MainRouter(object):

    db_name_master = 'default'
    db_name_slave = 'slave'

    def db_for_read(self, model, **hints):
        """
        Reads go to slave if it exists, otherwise to master (default).
        """

        if self.db_name_slave in settings.DATABASES:
            return self.db_name_slave
        else:
            return self.db_name_master


    def db_for_write(self, model, **hints):
        """
        Writes always go to master (default).
        """
        return self.db_name_master

    def allow_relation(self, obj1, obj2, **hints):
        """
        Relations between objects are allowed if both objects are
        in the master/slave pool.
        """
        db_list = (self.db_name_master, self.db_name_slave)
        if obj1._state.db in db_list and obj2._state.db in db_list:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        All models end up in this pool.
        """
        return True