# Password Manager

## Preamble

This whole guide is based on Ubuntu 14.04 LTS. Ubuntu 12.04+ LTS and Debian based systems should be similar if not even
identical.

## Installation

1. Install some generic stuff

        sudo apt-get update
        sudo apt-get install libyaml-dev libpython2.7-dev libpq-dev libffi-dev python-dev python-pip python-psycopg2
        sudo pip install -r requirements.txt
 
2. Install a database

    We will be using postgres (tested with version 9.5):

        sudo apt-get install postgresql postgresql-contrib
        sudo su - postgres
        createdb password_manager_server
        psql password_manager_server
        CREATE USER password_manager_server WITH PASSWORD 'password';
        GRANT ALL PRIVILEGES ON DATABASE "password_manager_server" to password_manager_server;
        CREATE EXTENSION IF NOT EXISTS ltree;
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        
    If you want to use this database for unit testing, you should also do:
           
        ALTER USER password_manager_server CREATEDB;
        
    To exit this shell and return to your normal user do:
        
        \q
        Ctrl + D
    
    Other databases are not supported because of missing ltree extension
    
3. Install the config

        cp configs/mainconfig/settings.yaml /home/your-user/.password_manager_server/settings.yaml

    **Update database credentials / secrets / paths and other settings you want to change in
    /home/your-user/.password_manager_server/settings.yaml**
    
4. Create our database

        ./password_manager_server/manage.py migrate


From this point on you should already be ready to run a test server. If you want to run this in production you should
make some additional steps. Depending on the webserver of your choice you can follow one of the two following
instructions to get a production server running


#### (optional) Installation addition for production server (with Apache)

1. Disable Debug Mode

    In /home/your-user/.password_manager_server/settings.yaml change
        
        DEBUG=True
        
    to 
    
        DEBUG=False
        
    in the same file, change the values for SECRET_KEY, ACTIVATION_LINK_SECRET and other values like EMAIL_FROM

2. Install Apache

        sudo apt-get update
        sudo apt-get install apache2
    
3. Install Apache modules

        sudo a2enmod headers
        
4. Install Apache config

        sudo ln -s /path/to/password-manager-server/configs/apache/dev.psono.pw.conf /etc/apache2/sites-enabled/
        
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
    
        */5 * * * * /path/to/password-manager-server/password_manager_server/manage.py cleartoken

#### (optional) Installation addition for production server (with Nginx)

1. Install dependencies

        sudo pip install uwsgi
        
    To test, issue the following command:
    
        uwsgi --http :9966 --chdir /path/to/password-manager-server/password_manager_server -w password_manager_server.wsgi
        
    and go to:
    
        http://your-ip:9966
        
    You should see something :)
        
2. Install nginx

        sudo apt-get update
        sudo apt-get install nginx
        
    If you go now to http://your-ip you should see "Welcome to nginx" page
        
3. Install nginx config

        sudo ln -s /path/to/password-manager-server/configs/nginx/dev.psono.pw.conf /etc/nginx/sites-enabled/
        
    change the path specified in .conf according to your file structure and let's restart our nginx:
    
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
        
        sudo ln -s /path/to/password-manager-server/configs/nginx/password_manager_server.ini /etc/uwsgi/vassals/

    To test try (replace www-data-usr / -grp with the user you want):
    
        uwsgi --emperor /etc/uwsgi/vassals --uid www-data-usr --gid www-data-grp
        
    You can now visit your 
    
    
6. Automatic start on boot

    According to the django documentation "For many systems, the easiest (if not the best) way to do this is to use the rc.local file."

        sudo vi /etc/rc.local
        
    add the following line BEFORE "exit 0" (again, replace  www-data-usr / -grp with your username / group):
    
        /usr/local/bin/uwsgi --emperor /etc/uwsgi/vassals --uid www-data-usr --gid www-data-grp --daemonize /var/log/uwsgi-emperor.log
        
7. Install Cronjobs

    ... to clear all expired tokens regulary
    
        */5 * * * * /path/to/password-manager-server/password_manager_server/manage.py cleartoken

For more details about how to install nginx I would like to refer to the official django documentation (because it is so awesome!)
http://uwsgi-docs.readthedocs.org/en/latest/tutorials/Django_and_nginx.html


## Start Server

It depends if you only have a test server or a production server running. The production server is controlled by apache
or nginx / uwsgi.

#### Test Server
    ./password_manager_server/manage.py runserver 0.0.0.0:8001

visit http://your-ip:8001 You should see something :)

The demo jsclient can be found http://your-ip:8001/demo/jsclient/index.html

Directory listing doesn't work, so don't be surprised that /demo/jsclient/ throws an error

#### Production Server (Apache)

    sudo service apache2 start
    
#### Production Server (Nginx)

    sudo service nginx start
    
visit https://your-ip You should see something :)

The demo jsclient can be found https://your-ip/demo/jsclient/index.html

## Update Server (Test or Production)

    ./password_manager_server/manage.py makemigrations restapi [only while developing]
    ./password_manager_server/manage.py migrate

## Run Unit Tests (with coverage)
To run unit tests, the database user needs CREATEDB rights.

    coverage run --source='.' ./password_manager_server/manage.py test restapi.tests
    
To get a nice report one can do:
    
    coverage report --omit=password_manager_server/restapi/migrations/*,password_manager_server/middleware/*,password_manager_server/restapi/tests*
    
or:

    coverage html --omit=password_manager_server/restapi/migrations/*,password_manager_server/middleware/*,password_manager_server/restapi/tests*
    
    The output of this command can be shown on https://your-ip/htmlcov/

## Production Server checks

1. Check Debug Mode is disabled:

    In the following configuration file:
    
    /home/your-user/.password_manager_server/settings.yaml
    
    debug needs to be false, so the following line needs to exist:
    
        DEBUG=False
        
2. SSL check:

    Best practise is always to check that your website is secured with SSL, therefore go to:
    
    https://www.ssllabs.com/ssltest/
    
    and let your website analyze


## LICENSE

Visit the [License.md](/LICENSE.md) for more details

