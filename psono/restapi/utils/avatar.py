from google.oauth2 import service_account
from django.conf import settings
from django.core.files.storage import get_storage_class
def get_avatar_storage():
    """
    Returns the avatar storage if a specific storage is configured, otherwise None
    """
    storage = None
    if settings.AVATAR_STORAGE:
        if (
                settings.AVATAR_STORAGE['class'] == 'google_cloud' and
                'kwargs' in settings.AVATAR_STORAGE and
                'credentials' in settings.AVATAR_STORAGE['kwargs'] and
                isinstance(settings.AVATAR_STORAGE['kwargs']['credentials'], dict)
        ):
            settings.AVATAR_STORAGE['kwargs']['credentials'] = service_account.Credentials.from_service_account_info(
                settings.AVATAR_STORAGE['kwargs']['credentials']
            )

        storage = get_storage_class(
            settings.AVAILABLE_AVATAR_STORAGES[settings.AVATAR_STORAGE['class']]
        )(**settings.AVATAR_STORAGE['kwargs'])
    return storage

def delete_avatar_storage_of_user(user_id):
    """
    Deletes the avatar storage of a user
    """
    storage = get_avatar_storage()
    if storage:
        files = storage.listdir(f"{settings.AVATAR_STORAGE_PREFIX}{user_id}".lower())[1]
        for file_name in files:
            file_path = f"{settings.AVATAR_STORAGE_PREFIX}{user_id}/{file_name}".lower()
            if storage.exists(file_path):
                storage.delete(file_path)
