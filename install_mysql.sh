sudo apt update
sudo apt install mysql-server
# make it listen externally
sed -i 's/^#bind-address .*$/bind-address    = 0.0.0.0/g' /etc/mysql/my.conf
# autostart
sudo systemctl enable mysql.service
sudo systemctl start mysql.service
# create database, table, and user
mysql -u root < init.sql