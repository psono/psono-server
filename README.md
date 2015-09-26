# Password Manager

## Installation

1. Install some generic stuff

        sudo apt-get update
        sudo apt-get install libpq-dev python-dev python-pip
        sudo pip install -r requirements.txt
 
2. Install a database

    We recommend using postgres for which we provide here the setup guide:

        sudo apt-get install postgresql postgresql-contrib
        sudo su - postgres
        createdb password_manager_server
        psql template1
        CREATE USER password_manager_server WITH PASSWORD 'password';
        GRANT ALL PRIVILEGES ON DATABASE "password_manager_server" to password_manager_server;
        \q
        Ctrl + D
    
    If you want another DB, please visit https://docs.djangoproject.com/en/1.8/ref/databases/ for details.
    
3. Install the config

        cp configs/mainconfig/settings.yaml /home/your-user/.password_manager_server/settings.yaml

    **Update database credentials / secrets / paths and other settings you want to change in
    /home/your-user/.password_manager_server/settings.yaml**
    
4. Create our database

        ./password_manager_server/manage.py migrate
    
#### Test Server
In /home/your-user/.password_manager_server/settings.yaml change
    
    DEBUG=False
    
to 

    DEBUG= True

#### Production Server

From this point on you should already be ready to run a test server. If you want to run this in production you should
make some additional steps.

TODO Install Apache
TODO Install Apache modules
TODO Install Apache site
TODO Install Apache SSL Key

install a cronjob to clear all expired tokens regulary

    */5 * * * * /path/to/manage.py cleartoken


## Start Server

It depends if you only have a test server or a production server running. The production server is controled by apache.

#### Test Server
    ./password_manager_server/manage.py runserver 0.0.0.0:8001

visit http://your-ip:8001 You should see something :)
The demo jsclient can be found http://your-ip:8001/demo/jsclient/index.html

#### Production Server

    sudo service apache2 start
    
visit https://your-ip You should see something :)
The demo jsclient can be found https://your-ip/demo/jsclient/index.html

## Update Server (Test or Production)

    ./password_manager_server/manage.py makemigrations restapi [only while developing]
    ./password_manager_server/manage.py migrate

## Run Unit Tests
    cd password_manager_server/
    ./manage.py test


## LICENSE

Visit the [License.md](/LICENSE.md) for more details

