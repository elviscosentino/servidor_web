#!/bin/bash

# curl -s https://raw.githubusercontent.com/elviscosentino/servidor_web/main/instalador.sh | bash

termcols=$(tput cols)
bold="$(tput bold)"
underline="$(tput smul)"
standout="$(tput smso)"
normal="$(tput sgr0)"
black="$(tput setaf 0)"
red="$(tput setaf 1)"
green="$(tput setaf 2)"
yellow="$(tput setaf 3)"
blue="$(tput setaf 4)"
magenta="$(tput setaf 5)"
cyan="$(tput setaf 6)"
white="$(tput setaf 7)"

clear
echo
echo "${bold}${blue}================================================================================${normal}"
echo
echo "${bold}Bem vindo ao super instalador de servidor Apache + PHP 8.3 + MariaDB 11.2 + PHPMyadmin + Composer 2.6.6 + Node.js 20.x"
echo "Criado por Elvis Cosentino"
echo
echo "${bold}${blue}================================================================================${normal}"
echo

user="$(whoami)"
if [ $user = "root" ];then
    echo "${bold}${red}Este script nÃ£o pode ser iniciado como Super UsuÃ¡rio!"
    echo "A instalaÃ§Ã£o nÃ£o poderÃ¡ continuar!"
    echo
    exit 0
fi

echo "${bold}${yellow}Ã‰ importante que o servidor esteja com as Ãºltimas atualizaÃ§Ãµes!"
echo "${bold}${yellow}Se ainda nÃ£o foi rodado o comando ${green}sudo apt update && sudo apt upgrade${yellow},"
echo "${bold}${yellow}Ã© recomendÃ¡vel que faÃ§a isso antes de instalar."
read -p "Continuar? (S/N) " continuar < /dev/tty
if [ $continuar = "S" ] || [ $continuar = "s" ];then
    echo "${normal}"
else
    echo
    exit 0
fi
echo

echo "${bold}${yellow}AtenÃ§Ã£o: o domÃ­nio ou subdomÃ­nio a ser instalado,"
echo "deverÃ¡ jÃ¡ estar com o dns propagado para o ip pÃºblico deste servidor!"
read -p "Continuar? (S/N) " continuar < /dev/tty
if [ $continuar = "S" ] || [ $continuar = "s" ];then
    echo "${normal}"
else
    echo
    exit 0
fi

read -p "Digite o domÃ­nio que serÃ¡ criado (ou subdomÃ­nio): " dominio < /dev/tty
echo
myip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
domainip="$(dig +short $dominio @resolver1.opendns.com)"
echo "IP do domÃ­nio $dominio: $domainip"
echo "IP pÃºblico deste servidor: $myip"
echo
if [ $myip != $domainip ];then
    echo "${bold}${red}O IP do domÃ­nio informado nÃ£o Ã© o mesmo deste servidor!"
    echo "A instalaÃ§Ã£o nÃ£o poderÃ¡ continuar!"
    echo
    exit 0
fi

read -p "Digite a pasta que serÃ¡ criada para a hospedagem (ficarÃ¡ em /var/www/): " pasta < /dev/tty
echo

read -p "Instalar o certificado SSL? (S/N) " instalarssl < /dev/tty
if [ $instalarssl = "S" ] || [ $instalarssl = "s" ];then
    read -p "Digite o e-mail para registro do certificado: " email < /dev/tty
fi
echo

read -p "Instalar o MariaDB? (S/N) " instalarmariadb < /dev/tty
if [ $instalarmariadb = "S" ] || [ $instalarmariadb = "s" ];then
    read -sp "Digite a senha do banco de dados: " bancosenha < /dev/tty
fi
echo

read -p "Instalar o PHPMyAdmin? (S/N) " instalarphpmyadmin < /dev/tty
if [ $instalarphpmyadmin = "S" ] || [ $instalarphpmyadmin = "s" ];then
    read -p "Digite o domÃ­nio que serÃ¡ criado para o PhpMyAdmin (ou subdomÃ­nio): " dominiophpmyadmin < /dev/tty
fi
echo

read -p "Instalar o Composer? (S/N) " instalarcomposer < /dev/tty
echo

read -p "Instalar o NodeJS? (S/N) " instalarnode < /dev/tty
echo


# alterar o timezone do servidor para o Brasil
echo "${bold}${green}===== ALTERANDO O TIMEZONE DO SERVIDOR PARA O BRASIL =====${normal}"
sudo timedatectl set-timezone America/Sao_Paulo && timedatectl
dataini="$(date)"
echo
echo "Inicio: $dataini"



# instala o servidor apache, php 8.3 e suas dependencias
echo "${bold}${green}===== INSTALANDO O APACHE, PHP 8.3 E DEPENDÃŠNCIAS =====${normal}"
sudo ufw allow ssh && sudo ufw allow http && sudo ufw allow https && echo "y" | sudo ufw enable
sudo add-apt-repository ppa:ondrej/php -y
sudo apt update
sudo apt install lsb-release ca-certificates apt-transport-https software-properties-common -y
sudo apt install php8.3 php8.3-cli php8.3-mysql php8.3-mbstring php8.3-xml php8.3-gd php8.3-curl php8.3-zip php8.3-imagick php8.3-bcmath -y
sudo usermod -aG www-data $USER



# instala e configura o certificado https
if [ $instalarcomposer = "S" ] || [ $instalarcomposer = "s" ];then
    echo "${bold}${green}===== INSTALANDO CERTIFICADO SSL PARA ACESSO HTTPS =====${normal}"
    sudo apt install certbot python3-certbot-apache -y
    #sudo certbot certonly --apache --agree-tos -n -d $dominio -m $email
    sudo certbot certonly --manual --preferred-challenges=dns --agree-tos -d $dominio -d *.$dominio -m $email
echo "
# Comando para emissÃ£o de certificado
sudo certbot certonly --manual --preferred-challenges=dns --non-interactive --agree-tos -d $dominio -d *.$dominio -m $email

# Reinicie o Apache ou o serviÃ§o web correspondente
sudo systemctl restart apache2" | sudo tee ~/renovar_certificado.sh
    sudo chmod 777 ~/renovar_certificado.sh
    echo "0  0    1 * *   root    /home/ubuntu/renovar_certificado.sh" | sudo tee -a /etc/crontab
fi



# configura pasta base e dados para conexao do site
echo "${bold}${green}===== CONFIGURANDO A PASTA BASE E PARÃ‚METROS DO APACHE =====${normal}"
sudo mkdir /var/www/$pasta && sudo chown root:www-data /var/www/$pasta -R && sudo chmod 777 /var/www/$pasta -R
echo "<VirtualHost *:80>
        ServerName $dominio
        ServerAlias *.$dominio

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/$pasta/public

        ErrorLog \${APACHE_LOG_DIR}/error.log
        CustomLog \${APACHE_LOG_DIR}/access.log combined

        RewriteEngine on
        RewriteCond %{SERVER_NAME} =$dominio [OR]
        RewriteCond %{SERVER_NAME} =www.$dominio
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
        <VirtualHost *:443>
                ServerName $dominio
                ServerAlias www.$dominio *.$dominio
                ServerAdmin webmaster@localhost

                DocumentRoot /var/www/$pasta/public

                <Directory \"/var/www/$pasta\">
                        Options Indexes FollowSymLinks
                        AllowOverride All
                        Require all granted
                </Directory>
                ErrorLog \${APACHE_LOG_DIR}/error.log
                CustomLog \${APACHE_LOG_DIR}/access.log combined

                SSLEngine on
                <FilesMatch \"\.(cgi|shtml|phtml|php)$\">
                        SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                        SSLOptions +StdEnvVars
                </Directory>

                SSLCertificateFile    /etc/letsencrypt/live/$dominio/fullchain.pem
                SSLCertificateKeyFile /etc/letsencrypt/live/$dominio/privkey.pem
                Include /etc/letsencrypt/options-ssl-apache.conf
        </VirtualHost>
</IfModule>" | sudo tee /etc/apache2/sites-available/$dominio.conf
cd /etc/apache2/sites-enabled && sudo ln -s /etc/apache2/sites-available/$dominio.conf && sudo unlink /etc/apache2/sites-enabled/000-default.conf
sudo a2enmod ssl && sudo a2enmod rewrite
sudo sed -i 's/memory_limit = 128M/memory_limit = 1024M/g' /etc/php/8.3/apache2/php.ini
sudo sed -i 's/post_max_size = 8M/post_max_size = 100M/g' /etc/php/8.3/apache2/php.ini
sudo sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 100M/g' /etc/php/8.3/apache2/php.ini
sudo systemctl restart apache2



# instala o composer 2.6.6 -- https://getcomposer.org/
if [ $instalarcomposer = "S" ] || [ $instalarcomposer = "s" ];then
    echo "${bold}${green}===== INSTALANDO O COMPOSER 2.6.6 =====${normal}"
    cd ~
    php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
    sudo php composer-setup.php --version=2.6.6 --install-dir=/usr/local/bin --filename=composer
    sudo rm /home/$USER/composer-setup.php
fi

# instala o node.js 20.x -- https://deb.nodesource.com/
if [ $instalarnode = "S" ] || [ $instalarnode = "s" ];then
    echo "${bold}${green}===== INSTALANDO O NODE.JS 20.x =====${normal}"
    sudo apt install -y ca-certificates curl gnupg
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    NODE_MAJOR=20
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
    sudo apt update && sudo apt install nodejs -y
fi


# instala o mariadb 11.2
if [ $instalarmariadb = "S" ] || [ $instalarmariadb = "s" ];then
    echo "${bold}${green}===== INSTALANDO O SERVIDOR DE BANCO DE DADOS MARIADB 11.2 =====${normal}"
    sudo apt-get install apt-transport-https curl
    sudo mkdir -p /etc/apt/keyrings
    sudo curl -o /etc/apt/keyrings/mariadb-keyring.pgp 'https://mariadb.org/mariadb_release_signing_key.pgp'
    echo "# MariaDB 11.2 repository list - created 2024-01-25 14:39 UTC
    # https://mariadb.org/download/
    X-Repolib-Name: MariaDB
    Types: deb
    # deb.mariadb.org is a dynamic mirror if your preferred mirror goes offline. See https://mariadb.org/mirrorbits/ for details.
    # URIs: https://deb.mariadb.org/11.2/ubuntu
    URIs: https://mirrors.xtom.com/mariadb/repo/11.2/ubuntu
    Suites: jammy
    Components: main main/debug
    Signed-By: /etc/apt/keyrings/mariadb-keyring.pgp" | sudo tee /etc/apt/sources.list.d/mariadb.sources
    sudo apt update
    sudo apt install mariadb-server -y

    #sudo mariadb -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'Iddqd1@Iddqd1#';FLUSH PRIVILEGES;"
    #sudo mariadb -u "root" "-pIddqd1@Iddqd1#" -e "CREATE DATABASE crm;USE crm;CREATE USER 'palterm'@'localhost' IDENTIFIED BY '$bancosenha';GRANT ALL PRIVILEGES ON crm.* TO 'palterm'@'localhost';FLUSH PRIVILEGES;"
    #sudo mariadb -u "root" -e "CREATE DATABASE crm;USE crm;CREATE USER 'palterm'@'localhost' IDENTIFIED BY '$bancosenha';GRANT ALL PRIVILEGES ON crm.* TO 'palterm'@'localhost';FLUSH PRIVILEGES;"
    #sudo mariadb -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'Iddqd1@Iddqd1#';FLUSH PRIVILEGES;"
    #sudo mariadb -u "root" "-pIddqd1@Iddqd1#" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'Iddqd1@Iddqd2';FLUSH PRIVILEGES;"
    #ALTER USER 'root'@'localhost' IDENTIFIED BY 'Iddqd1@Iddqd1#';
    #FLUSH PRIVILEGES;
    #exit
fi


# instala o phpmyadmin
if [ $instalarphpmyadmin = "S" ] || [ $instalarphpmyadmin = "s" ];then
    sudo apt install php8.3-common php8.2-mcrypt php8.3-bz2 php8.3-mysql
    sudo apt install phpmyadmin -y
    sudo ln -s /usr/share/phpmyadmin /var/www/phpmyadmin
    sudo certbot certonly --apache --agree-tos -n -d $dominiophpmyadmin -m $email
    echo "<VirtualHost *:80>
        ServerName $dominiophpmyadmin

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/phpmyadmin

        ErrorLog \${APACHE_LOG_DIR}/error.log
        CustomLog \${APACHE_LOG_DIR}/access.log combined

        RewriteEngine on
        RewriteCond %{SERVER_NAME} =$dominiophpmyadmin
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
        <VirtualHost *:443>
                ServerName $dominiophpmyadmin
                ServerAdmin webmaster@localhost

                DocumentRoot /var/www/phpmyadmin

                <Directory \"/var/www/phpmyadmin\">
                        Options Indexes FollowSymLinks
                        AllowOverride All
                        Require all granted
                </Directory>
                ErrorLog \${APACHE_LOG_DIR}/error.log
                CustomLog \${APACHE_LOG_DIR}/access.log combined

                SSLEngine on
                <FilesMatch \"\.(cgi|shtml|phtml|php)$\">
                        SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                        SSLOptions +StdEnvVars
                </Directory>

                SSLCertificateFile    /etc/letsencrypt/live/$dominiophpmyadmin/fullchain.pem
                SSLCertificateKeyFile /etc/letsencrypt/live/$dominiophpmyadmin/privkey.pem
                Include /etc/letsencrypt/options-ssl-apache.conf
        </VirtualHost>
</IfModule>" | sudo tee /etc/apache2/sites-available/$dominiophpmyadmin.conf
    cd /etc/apache2/sites-enabled && sudo ln -s /etc/apache2/sites-available/$dominiophpmyadmin.conf
    sudo systemctl restart apache2

    #sudo mariadb -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'Iddqd1@Iddqd1#';FLUSH PRIVILEGES;"
fi


datafim="$(date)"
echo
echo "Iniciou as : $dataini"
echo "Terminou as: $datafim"
echo
echo "${bold}${green}====== FIM DA INSTALACAO =====${normal}"
echo
