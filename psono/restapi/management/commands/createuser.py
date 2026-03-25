from django.core.management.base import BaseCommand

from restapi.utils import create_user


class Command(BaseCommand):
    help = "Creates a user with given password"

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("password")
        parser.add_argument("email")

        parser.add_argument(
            "--show-password",
            action="store_true",
            dest="show_password",
            help="Shows the password in the completion success message in plain text",
        )

        parser.add_argument(
            "--require-password-change",
            action="store_true",
            dest="require_password_change",
            help="Marks the created user to require a password change on next login",
        )

    def handle(self, *args, **options):

        username = options["username"]
        password = options["password"]
        email = options["email"]

        result = create_user(username, password, email)

        if "error" in result:
            self.stdout.write(result["error"])
            return

        if options["require_password_change"]:
            user = result["user"]
            user.require_password_change = True
            user.save(update_fields=["require_password_change"])

        if not options["show_password"]:
            password = "******"  # nosec

        self.stdout.write(
            'Created user "'
            + username
            + '" with password "'
            + password
            + '" and email "'
            + email
            + '"'
        )
