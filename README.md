# PSONO Server - Password Manager

Master: [![Code Climate](https://codeclimate.com/github/psono/psono-server/badges/gpa.svg)](https://codeclimate.com/github/psono/psono-server) [![build status](https://images.microbadger.com/badges/image/psono/psono-server.svg)](https://hub.docker.com/r/psono/psono-server/) [![build status](https://gitlab.com/psono/psono-server/badges/master/build.svg)](https://gitlab.com/psono/psono-server/commits/master) [![coverage report](https://gitlab.com/psono/psono-server/badges/master/coverage.svg)](https://gitlab.com/psono/psono-server/commits/master)

Develop: [![build status](https://gitlab.com/psono/psono-server/badges/develop/build.svg)](https://gitlab.com/psono/psono-server/commits/develop) [![coverage report](https://gitlab.com/psono/psono-server/badges/develop/coverage.svg)](https://gitlab.com/psono/psono-server/commits/develop)

# Canonical source

The canonical source of PSONO Server is [hosted on GitLab.com](https://gitlab.com/psono/psono-server).

# Preamble

This whole guide is based on Ubuntu 16.04 LTS. Ubuntu 12.04+ LTS and Debian based systems should be similar if not even
identical.

# Installation

## Postgres (if you do not already have one)

We will be using postgres (tested with version 9.6, but every 9.x version should work):

1. First install some requirements
    
        sudo apt-get install postgresql postgresql-contrib
   
2. Now lets switch the postgres user
    
        sudo su - postgres

3. Create our new DB
    
        createdb psono

4. Now switch the command prompt to postgres command prompt

        psql psono
    
5. Followed by some nice postgres commands to create the user and grant all privileges:
        
        CREATE USER psono WITH PASSWORD 'password';
        GRANT ALL PRIVILEGES ON DATABASE "psono" to psono;

6. Install some extensions:

        CREATE EXTENSION IF NOT EXISTS ltree;
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    
7. (optional) If you want to use this database for unit testing, you should also do:
           
        ALTER USER psono CREATEDB;
    
8. To exit this shell and return to your normal user do:
        
        \q
        Ctrl + D
    
    Other databases are not supported because of missing ltree extension


## Docker (easiest way)

We assume that you already have a postgres database running. If not follow the guide above to install one.

1. Prepare settings.yaml

    Copy the settings.yaml to a location of your choice, e.g /opt/docker/psono/
    
        mkdir -p /opt/docker/psono
        cp /path/to/settings.yaml /opt/docker/psono/settings.yaml
    
    **Update database credentials / secrets / paths like described in the comments of
    /home/your-user/.psono_server/settings.yaml**

2. Test E-Mail

    The most tedious step is usually for me to get e-mail working.
    To make this step easier, we offer a small test script which will
    send a test e-mail.
    
    To send a test e-mail to `something@something.com` execute:

        docker run --rm \
          -v /path/to/modified/settings.yaml:/root/.psono_server/settings.yaml \
          -ti psono/psono-server:latest psono/manage.py sendtestmail something@something.com

    If you receive this test e-mail, e-mail should be configured proper.
    
3. Prepare the database

        docker run --rm \
          -v /path/to/modified/settings.yaml:/root/.psono_server/settings.yaml \
          -ti psono/psono-server:latest psono/manage.py migrate
    
4. Run the dockered psono server image and expose the server port

        docker run --name psono-server \
            -v /path/to/modified/settings.yaml:/root/.psono_server/settings.yaml \
            -d --restart=unless-stopped -p 10100:80 psono/psono-server:latest 
            
        
    Possible (optional) environment variables are:
    
        PSONO_SECRET_KEY
        PSONO_ACTIVATION_LINK_SECRET
        PSONO_WEB_CLIENT_URL
        PSONO_DB_SECRET
        PSONO_EMAIL_SECRET_SALT
        PSONO_DEBUG
        PSONO_ALLOWED_HOSTS
        PSONO_ALLOWED_DOMAINS
        PSONO_DATABASES
        PSONO_EMAIL_FROM
        PSONO_EMAIL_HOST
        PSONO_EMAIL_HOST_USER
        PSONO_EMAIL_HOST_PASSWORD
        PSONO_EMAIL_PORT
        PSONO_EMAIL_SUBJECT_PREFIX
        PSONO_EMAIL_USE_TLS
        PSONO_EMAIL_USE_SSL
        PSONO_EMAIL_SSL_CERTFILE
        PSONO_EMAIL_SSL_KEYFILE
        PSONO_EMAIL_TIMEOUT
        PSONO_YUBIKEY_CLIENT_ID
        PSONO_YUBIKEY_SECRET_KEY


    If you open now http://your-ip:10100 you should see something like this:

        {"detail":"Authentication credentials were not provided."}

    If not, please make sure you have no firewall on the server blocking you.

    Proceed with the the installation of the psono client here:
    https://gitlab.com/psono/psono-client



## Bare installation (if not Docker)

We assume that you already have a postgres database running. If not follow the guide above to install one.

1. Install some generic stuff

        sudo apt-get update
        sudo apt-get install libyaml-dev libpython2.7-dev libpq-dev libffi-dev python-dev python-pip python-psycopg2
        sudo pip install -r requirements.txt
    
3. Install the config

        cp configs/mainconfig/settings.yaml /home/your-user/.psono_server/settings.yaml

    **Update database credentials / secrets / paths like described in the comments of
    /home/your-user/.psono_server/settings.yaml**
    
4. Test E-Mail

    The most tedious step is usually for me to get e-mail working.
    To make this step easier, we offer a small test script which will
    send a test e-mail.
    
    To send a test e-mail to `something@something.com` execute:

        ./psono/manage.py sendtestmail something@something.com

    If you receive this test e-mail, e-mail should be configured proper.
    
5. Create our database

        ./psono/manage.py migrate


From this point on you should already be ready to run a test server. If you want to run this in production you should
make some additional steps. Depending on the webserver of your choice you can follow one of the two following
instructions to get a production server running


#### (optional) Installation addition for production server (with Apache)

1. Disable Debug Mode

    In /home/your-user/.psono_server/settings.yaml change
        
        DEBUG=True
        
    to 
    
        DEBUG=False
        
    in the same file, change the values for SECRET_KEY, ACTIVATION_LINK_SECRET and other values like EMAIL_FROM

2. Install Apache

        sudo apt-get update
        sudo apt-get install apache2
    
3. Install Apache modules

        sudo a2enmod headers
        sudo a2enmod ssl
        
4. Install Apache config

        sudo cp /path/to/psono-server/configs/apache/psono.pw.conf /etc/apache2/sites-enabled/
        
    change the path specified in .conf according to your file structure and let's restart our apache:
    
        sudo service apache2 restart

5. Create and Install ssl certificates

    If you are not so familiar with SSL you should comment out the line with "Strict-Transport-Security... in nginx
    .conf file before testing and proceeding with the rest below till really everything works, and comment it back in.
    This can be a "pain in the ass" and lead to "misleading" conclusions later.

    TODO Generation of certificates
    TODO Installation of certificates
        
6. Install Cronjobs

    ... to clear all expired tokens regulary
    
        30 2 * * * /path/to/psono-server/psono/manage.py cleartoken

#### (optional) Installation addition for production server (with Nginx)

1. Install dependencies

        sudo pip install uwsgi
        
    To test, issue the following command:
    
        uwsgi --http :9966 --chdir /path/to/psono-server/psono -w psono.wsgi
        
    and go to:
    
        http://your-ip:9966
        
    You should see something :)
        
2. Install nginx

        sudo apt-get update
        sudo apt-get install nginx
        
    If you go now to http://your-ip you should see "Welcome to nginx" page
        
3. Install nginx config

        sudo cp /path/to/psono-server/configs/nginx/psono.pw.conf /etc/nginx/sites-enabled/
        
    change the domain and path specified in .conf accordingly and let's restart our nginx:
    
        sudo service nginx restart
        
        
4. Create and Install ssl certificates

    If you are not so familiar with SSL you should comment out the line with "Strict-Transport-Security... in nginx
    .conf file before testing and proceeding with the rest below till really everything works, and comment it back in.
    This can be a "pain in the ass" and lead to "misleading" conclusions later.

    TODO Generation of certificates
    
    TODO Installation of certificates
    
    
5. Install emperor mode

    To install emperor we have to create a couple of folders and a symbolic link to our ini:

        sudo mkdir /etc/uwsgi
        sudo mkdir /etc/uwsgi/vassals
        
        sudo ln -s /path/to/psono-server/configs/nginx/psono_uwsgi.ini /etc/uwsgi/vassals/

    To check if everything is configured correctly try the following (replace www-data-usr / -grp with the user you want):
    
        uwsgi --emperor /etc/uwsgi/vassals --uid www-data-usr --gid www-data-grp
        
    If no errors are reported, everything should be fine.
    
    
6. Automatic start on boot

    According to the django documentation "For many systems, the easiest (if not the best) way to do this is to use the rc.local file."

        sudo vi /etc/rc.local
        
    add the following line BEFORE "exit 0" (again, replace  www-data-usr / -grp with your username / group):
    
        /usr/local/bin/uwsgi --emperor /etc/uwsgi/vassals --uid www-data-usr --gid www-data-grp --daemonize /var/log/uwsgi-emperor.log
        
7. Install Cronjobs

    ... to clear all expired tokens regulary
    
        30 2 * * * /path/to/psono-server/psono/manage.py cleartoken

For more details about how to install nginx I would like to refer to the official django documentation (because it is so awesome!)
http://uwsgi-docs.readthedocs.org/en/latest/tutorials/Django_and_nginx.html


## Start Server

It depends if you only have a test server or a production server running. The production server is controlled by apache
or nginx / uwsgi.

#### Test Server
    ./psono/manage.py runserver 0.0.0.0:8001

visit http://your-ip:8001 You should see something :)

#### Production Server (Apache)

    sudo service apache2 start
    
#### Production Server (Nginx)

    sudo service nginx start
    
visit https://your-ip You should see something :)

## Update Server (Test or Production)

    ./psono/manage.py makemigrations restapi [only while developing]
    ./psono/manage.py migrate

## Run Unit Tests (with coverage)
To run unit tests, the database user needs CREATEDB rights.

    coverage run --source='.' ./psono/manage.py test restapi.tests
    
To get a nice report one can do:
    
    coverage report --omit=psono/restapi/migrations/*,psono/middleware/*,psono/restapi/tests*
    
or:

    coverage html --omit=psono/restapi/migrations/*,psono/middleware/*,psono/restapi/tests*
    
    The output of this command can be shown on https://your-ip/htmlcov/

## Run local dummy smtp server

If you want to debug e-mails, like those sent during the registration, one can start a
local dummy smtp server with the following command

    sudo python -m smtpd -n -c DebuggingServer localhost:25

## Audit Logging

For companies audibility is a big point. To enable audit logs add the following two lines to your settings.yml:

    LOGGING_AUDIT: True
    LOGGING_AUDIT_FOLDER: '/path/to/audit/log/folder'
    LOGGING_AUDIT_TIME: 'time_server' # (optional) if you prefer server time over utc time
    
This will show report to the client in the `info/` request, that audit logging is enabled.
The client will show this as a warning to the user before login and requires the users approval.
Afterwards the client will send some additional data for audibility purposes.

>INFO: This feature is not enabled on the psono.pw server and is not enabled by default

>WARNING: This feature may be removed without notice in any future version.


## Production Server checks

1. Check Debug Mode is disabled:

    In the following configuration file:
    
    /home/your-user/.psono_server/settings.yaml
    
    debug needs to be false, so the following line needs to exist:
    
        DEBUG=False
        
2. SSL check:

    Best practise is always to check that your website is secured with SSL, therefore go to:
    
    https://www.ssllabs.com/ssltest/
    
    and let your website analyze

3. Protect your settings.yaml

    Your settings.yaml contains sensitive information. Use the proper access rights
    
        chmod 600 /home/your-user/.psono_server/settings.yaml

4. Healthchecks

    Healthschecks are implemented for the ressource /healthcheck/.
    In case of a failure the ressource will return something different than 200 with usually some details about whats
    wrong.

## Backup & Restore

For a full backup, you have to backup two things. First thing obviously is the database, and the second thing is your
settings.yaml file as it contains some secrets necessary to decrypt the data in your database.
We have created two little scripts to backup and restore your files in var/backup

#### Backup Process:

For backups follow the following steps.

1. Copy var/backup to a folder of your choosing, example:

        sudo cp -R var/backup /opt/psono-backup
    
2. Update .env file in /opt/psono-backup

3. Execute the backup like:

        /opt/psono-backup/backup
    
4. Schedule backups e.g. for 2:30am daily:

        crontab -e
    
    and add this line:
    
        30 2 * * * /opt/psono-backup/backup

5. Check that backups are created proper a day later.

    If you experience any errors you can check your logs for tips why:
    
        grep CRON /var/log/syslog
        
    Common problems are insufficient user or database rights.


#### Restore Process:

For restoration of a backup follow the following steps.

1. Copy var/backup to a folder of your choosing, example:

        sudo cp -R var/backup /opt/psono-backup
    
2. Update .env file in /opt/psono-backup

3. Execute the backup like:

        /opt/psono-backup/restore --backup=path/to/the/backup/backup_12345.../

## LICENSE

Visit the [License.md](/LICENSE.md) for more details

