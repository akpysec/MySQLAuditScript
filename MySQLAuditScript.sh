#!/bin/bash
# MySQL 5.7 Security Audit Script CIS
# Use following command to run this scipt 
# chmod +x MySQL_AndreysNew.sh
# ./MySQL_AndreysNew.sh
# if getting error "BAD INTERPRETER, Path not found", use the following command and run script again after:
# sed -i -e 's/\r$//' MySQL_AndreysNew.sh


echo "Enter your username for mysql (root recommended)";
read username;
echo "Enter password (password not shown)";
unset password;
while IFS= read -r -s -n1 pass; do
  if [[ -z $pass ]]; then
     echo
     break
  else
     echo -n '*'
     password+=$pass
  fi
done



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "Security Audit Script" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "1 Operating System Level Configuration" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "1.1 Place Databases on Non-System Partitions" >> SEC_AUDIT.txt
echo "show variables where variable_name = 'datadir';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service" >> SEC_AUDIT.txt
ps -ef | egrep '^mysql.*$' | grep . >> SEC_AUDIT.txt || echo 'No Value found - THIS IS A FINDING' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "1.3 Disable MySQL Command History" >> SEC_AUDIT.txt
find /home -name ".mysql_history" | grep . && echo "For each file returned determine whether that file is symbolically linked to /dev/null." >> SEC_AUDIT.txt || echo 'No Value found - PASS' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "1.4 Verify That the MYSQL_PWD Environment Variables Is Not In Use" >> SEC_AUDIT.txt
grep MYSQL_PWD /proc/*/environ | grep . && echo "If only grep present than it's ok" >> SEC_AUDIT.txt || echo 'No Value found - PASS' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "1.5 Disable Interactive Login" >> SEC_AUDIT.txt
getent passwd mysql | egrep "^.*[\/bin\/false|\/sbin\/nologin]$" | grep . >> SEC_AUDIT.txt || echo 'No Value found - THIS IS A FINDING'>> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "1.6 Verify That 'MYSQL_PWD' Is Not Set In Users' Profiles" >> SEC_AUDIT.txt
grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt


echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "3 File System Permissions" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.2 Ensure 'log_bin_basename' Files Have Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables like 'log_bin_basename';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.3 Ensure 'log_error' Has Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables like 'log_error';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.4 Ensure 'slow_query_log' Has Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables like 'slow_query_log';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables like 'relay_log_basename';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.6 Ensure 'general_log_file' Has Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables like 'general_log_file';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.7 Ensure SSL Key Files Have Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables where variable_name = 'ssl_key';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "3.8 Ensure Plugin Directory Has Appropriate Permissions" >> SEC_AUDIT.txt
echo "show variables where variable_name = 'plugin_dir';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "Pulling list of directories & files permissions" >> SEC_AUDIT.txt
find / -type d -name "mysql" | while read line ; do ls -lah $line && echo $line ; done >> SEC_AUDIT.txt

sleep .5
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "4 General" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "4.2 Ensure the 'test' Database Is Not Installed" >> SEC_AUDIT.txt
echo "SHOW DATABASES LIKE 'test';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "4.4 Ensure 'local_infile' Is Disabled" >> SEC_AUDIT.txt
echo "SHOW VARIABLES WHERE Variable_name = 'local_infile';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "4.6 Ensure '--skip-symbolic-links' Is Enabled" >> SEC_AUDIT.txt
echo "SHOW variables LIKE 'have_symlink';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "4.7 Ensure the 'daemon_memcached' Plugin Is Disabled" >> SEC_AUDIT.txt
echo "SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "4.8 Ensure 'secure_file_priv' Is Not Empty" >> SEC_AUDIT.txt
echo "SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv' AND Value<>'';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES'" >> SEC_AUDIT.txt
echo "SHOW VARIABLES LIKE 'sql_mode';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "5 MySQL Permissions" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.1 Ensure Only Administrative Users Have Full Database Access" >> SEC_AUDIT.txt
echo "SELECT user, host
FROM mysql.user
WHERE (Select_priv = 'Y')
OR (Insert_priv = 'Y')
OR (Update_priv = 'Y')
OR (Delete_priv = 'Y')
OR (Create_priv = 'Y')
OR (Drop_priv = 'Y');
SELECT user, host
FROM mysql.db
WHERE db = 'mysql'
AND ((Select_priv = 'Y')
OR (Insert_priv = 'Y')
OR (Update_priv = 'Y')
OR (Delete_priv = 'Y')
OR (Create_priv = 'Y')
OR (Drop_priv = 'Y'));"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.2 Ensure 'file_priv' Is Not Set to 'Y' for Non-Administrative Users" >> SEC_AUDIT.txt
echo "SELECT user, host from mysql.user where File_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.3 Ensure 'process_priv' Is Not Set to 'Y' for Non-Administrative Users" >> SEC_AUDIT.txt
echo "SELECT user, host from mysql.user where Process_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.4 Ensure 'super_priv' Is Not Set to 'Y' for Non-Administrative Users" >> SEC_AUDIT.txt
echo "SELECT user, host from mysql.user where Super_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.5 Ensure 'shutdown_priv' Is Not Set to 'Y' for Non-Administrative Users" >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.user WHERE Shutdown_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.6 Ensure 'create_user_priv' Is Not Set to 'Y' for Non-Administrative Users" >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.user WHERE Create_user_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.7 Ensure 'grant_priv' Is Not Set to 'Y' for Non-Administrative Users" >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.user WHERE Grant_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.db WHERE Grant_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.8 Ensure 'repl_slave_priv' Is Not Set to 'Y' for Non-Slave Users" >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.user WHERE Repl_slave_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "5.9 Ensure DML/DDL Grants Are Limited to Specific Databases and Users" >> SEC_AUDIT.txt
echo "SELECT User,Host,Db
FROM mysql.db
WHERE Select_priv='Y'
OR Insert_priv='Y'
OR Update_priv='Y'
OR Delete_priv='Y'
OR Create_priv='Y'
OR Drop_priv='Y'
OR Alter_priv='Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "6 Auditing and Logging" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "6.1 Ensure 'log_error' Is Not Empty" >> SEC_AUDIT.txt
echo "SHOW variables LIKE 'log_error';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "6.2 Ensure Log Files Are Stored on a Non-System Partition" >> SEC_AUDIT.txt
echo "SELECT @@global.log_bin_basename;"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "6.3 Ensure 'log_error_verbosity' Is Not Set to '1'" >> SEC_AUDIT.txt
echo "SHOW GLOBAL VARIABLES LIKE 'log_error_verbosity';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "7 Authentication" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "7.2 Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'" >> SEC_AUDIT.txt
echo "SELECT @@global.sql_mode;"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "SELECT @@session.sql_mode;"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "7.3 Ensure Passwords Are Set for All MySQL Accounts" >> SEC_AUDIT.txt
echo "SELECT User,host FROM mysql.user WHERE authentication_string='';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "7.4 Ensure 'default_password_lifetime' Is Less Than Or Equal To '90'" >> SEC_AUDIT.txt
echo "SHOW VARIABLES LIKE 'default_password_lifetime';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "7.5 Ensure Password Complexity Is in Place" >> SEC_AUDIT.txt
echo "SHOW VARIABLES LIKE 'validate_password%';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "7.6 Ensure No Users Have Wildcard Hostnames" >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.user WHERE host = '%';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "7.7 Ensure No Anonymous Accounts Exist" >> SEC_AUDIT.txt
echo "SELECT user,host FROM mysql.user WHERE user = '';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "8 Network" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "8.1 Ensure 'have_ssl' Is Set to 'YES'" >> SEC_AUDIT.txt
echo "SHOW variables WHERE variable_name = 'have_ssl';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "8.2 Ensure 'ssl_type' Is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users" >> SEC_AUDIT.txt
echo "SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt



echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "9 Replication" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "9.2 Ensure 'MASTER_SSL_VERIFY_SERVER_CERT' Is Set to 'YES' or '1'" >> SEC_AUDIT.txt
echo "SELECT ssl_verify_server_cert from mysql.slave_master_info;"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "9.3 Ensure 'master_info_repository' Is Set to 'TABLE'" >> SEC_AUDIT.txt
echo "SHOW GLOBAL VARIABLES LIKE 'master_info_repository';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "9.4 Ensure 'super_priv' Is Not Set to 'Y' for Replication Users" >> SEC_AUDIT.txt
echo "SELECT user, host from mysql.user where user='repl' and Super_priv = 'Y';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt
echo "9.5 Ensure No Replication Users Have Wildcard Hostnames" >> SEC_AUDIT.txt
echo "SELECT user, host FROM mysql.user WHERE user='repl' AND host = '%';"| mysql -u$username -p$password | grep . >> SEC_AUDIT.txt || echo 'No Value found' >> SEC_AUDIT.txt
echo "--------------------------------------------------------------------------------------------------------------------------" >> SEC_AUDIT.txt

sleep .5

echo "==========================================================================================================================" >> SEC_AUDIT.txt
echo "Global Configurations stored in saperate file - GlobalConfigurations.txt" >> SEC_AUDIT.txt
echo "==========================================================================================================================" >> SEC_AUDIT.txt

sleep .5

mysql -u$username -p$password -A -e"SHOW GLOBAL VARIABLES;" > GlobalConfigurations.txt


echo "DONE! Output in th SEC_AUDIT.txt file"

