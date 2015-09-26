# Password Manager

## Installation
    sudo apt-get update
    sudo apt-get install libpq-dev python-dev python-pip
    sudo pip install -r requirements.txt
 
    TODO setup postgres user / database / ...
    
    cp configs/mainconfig/settings.yaml /home/your-user/.password_manager_server/settings.yaml

#### Production Server

From this point on you should already be ready to run a test server. If you want to run this in production you should
make some additional steps.

TODO

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

