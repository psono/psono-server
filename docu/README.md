# Useful commands

#### Prepare DB:

      ./psono/manage.py presetup

  To avoid rights problems and limit db user rights, the installation of extensions can be initiated with this command.
  
#### Test E-Mail:

      ./psono/manage.py sendtestmail email@something.com

  Little helper script to test the email setup

#### Register user through the commandline:

      ./psono/manage.py createuser username@example.com myPassword email@something.com

  Nice command to create a dummy user from commandline, to not go through the registration / validation process with
  email servers and so on.

#### Clear expired token

      ./psono/manage.py cleartoken
  
  This command should be executed regular in production environments (best by cron or something similar)