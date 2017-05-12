Procedimento instalação Graylog
===============================

# Instalação de Infra

## Instalar Java, EPEL e utilitários
```
yum install -y java-1.8.0-openjdk-headless epel-release policycoreutils-python
yum install -y pwgen sha256sum
```

## Instalar MongoDB
### Instalar o arquivo de repositório do MongoDB
Criar o arquivo de repositório ```/etc/yum.repos.d/mongodb-org-3.2.repo```:

```ini
[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-3.2.asc
```

### Instalar o Pacote do MongoDB
```
yum install -y mongodb-org
```

### Ajustar Regras SELinux para o MongoDB
```
semanage port -a -t mongod_port_t -p tcp 27017
```

### Habilitar e Inicializar o MongoDB
```
systemctl enable mongod.service
systemctl start mongod.service
```

## Instalar Elasticsearch

### Instalar o gpgkey do repositorio
```
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
```

Criar o arquivo de repositório ```/etc/yum.repos.d/elasticsearch.repo```:
```ini
[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=https://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
```

### Instalar o pacote do Elasticsearch
```
yum install -y elasticsearch
```
### Configuração do Elasticsearch
Editar o arquivo ```/etc/sysconfig/elasticsearch``` e ajustar o seguinte parâmetro:
```
ES_HEAP_SIZE=4g
MAX_LOCKED_MEMORY=4g
```

Editar o arquivo ```/etc/elasticsearch/elasticsearch.yml``` e ajustar os seguintes parâmetros:
```
cluster.name: graylog
bootstrap.memory_lock: true
index.codec: best_compression
cluster.routing.allocation.disk.threshold_enabled: True
cluster.routing.allocation.disk.watermark.low: 2gb
cluster.routing.allocation.disk.watermark.high: 4gb
```

Instalar o Kopf:
```
/usr/share/elasticsearch/bin/plugin install lmenezes/elasticsearch-kopf/2.1.1
```

Ajustar o parâmetro de uso de SWAP no Kernel no arquivo ```/etc/sysctl.conf```:
```
vm.swappiness = 1
```
E aplicar:
```
sysctl -p
```

## Habilitar e Iniciar o Elasticsearch
```
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
```

## Instalar Graylog

Instalar o Repositório
```yum
yum install -y https://packages.graylog2.org/repo/packages/graylog-2.2-repository_latest.rpm
```

Instalar o Graylog Server
```yum
yum install -y graylog-server
```

Editar o arquivo ```/etc/graylog/server/server.conf``` e configure os parâmetros:
```
password_secret
root_password_sha2
root_timezone = America/Sao_Paulo
elasticsearch_shards = 2
allow_leading_wildcard_searches = true
elasticsearch_cluster_name = graylog
message_journal_max_age = 12h
message_journal_max_size = 5gb
transport_email_*
#trusted_proxies = 127.0.0.1/32, 0:0:0:0:0:0:0:1/128
```

Para criar o ```password_secret```:
```
pwgen -N 1 -s 96
```

Para criar o ```root_password_sha2```:
```
echo -n <senha_root> | sha256sum
```

Instalar o Slack Output Plugin:
```yum
yum install -y https://github.com/Graylog2/graylog-plugin-slack/releases/download/2.4.0/graylog-plugin-slack-2.4.0-1.noarch.rpm
```

Instalar o GeoIP:
```
wget -O /etc/graylog/server/GeoLite2-City.mmdb.gz http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
gunzip -f /etc/graylog/server/GeoLite2-City.mmdb.gz
```

Configurar update semanal na Cron:
```
cat <<EOF >> /etc/cron.d/graylog
# Atualiza informações de GeoIP Semanalmente
0 12 * * 0    root    wget -O /etc/graylog/server/GeoLite2-City.mmdb.gz http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz && gunzip -f /etc/graylog/server/GeoLite2-City.mmdb.gz
EOF
```


### Habilitar e Iniciar o Graylog
```
systemctl enable graylog-server.service
systemctl start graylog-server.service
```

## Instalar Kibana

### Instalar o gpgkey do repositorio
```
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
```

Criar o arquivo de repositório ```/etc/yum.repos.d/kibana.repo```:
```ini
[kibana-4.6]
name=Kibana repository for 4.6.x packages
baseurl=https://packages.elastic.co/kibana/4.6/centos
gpgcheck=1
gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
```

### Instalar o pacote do Kibana
```
yum install -y kibana
```

Editar o arquivo ```/opt/kibana/config/kibana.yml``` e ajustar os seguintes parâmetros:
```
server.host: "127.0.0.1"
server.basePath: "/kibana"
```

## Habilitar e Iniciar o Kibana
```
systemctl enable kibana.service
systemctl start kibana.service
```

## Instalar o NGINX

### Baixar o pacote do NGINX (EPEL)
```
yum install -y nginx httpd-tools
```

### Habilitar no SELinux o Acesso do Nginx aos Backends
```
# porta TCP Graylog
semanage port -a -t http_port_t -p tcp 9000

# porta TCP Graylog
semanage port -a -t http_port_t -p tcp 5601
```

### Configuracao do NGINX

Comentar o ```location / {}``` dentro do ```/etc/nginx/nginx.conf```, pois este será utilizado pelo Graylog

Criar o arquivo ```/etc/nginx/default.d/graylog.conf``` com o seguinte conteúdo:
```nginx
location /kibana/ {
  auth_basic "Kibana Auth";
  auth_basic_user_file /etc/nginx/kibana.htpaswd;
  proxy_set_header    Host $http_host;
  proxy_set_header    X-Forwarded-Host $host;
  proxy_set_header    X-Forwarded-Server $host;
  proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_pass          http://127.0.0.1:5601/;
  }

location / {
  proxy_set_header    Host $http_host;
  proxy_set_header    X-Forwarded-Host $host;
  proxy_set_header    X-Forwarded-Server $host;
  proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header    X-Graylog-Server-URL http://$host/api;
  proxy_pass          http://127.0.0.1:9000/;
}
```

Configurar a autenticação do Kibana
```
htpasswd -c /etc/nginx/kibana.htpaswd kibanaadmin
```

### Habiliar e Iniciar o NGINX
```
systemctl enable nginx.service
systemctl start nginx.service
```


# Configurações de Segurança

## Habilitar autenticação do MongoDB
Conectar no mongo e criar o user admin:
```
mongo
> use admin
> db.createUser({ user: "admin", pwd: "<senha>", roles: [{ role: "userAdminAnyDatabase", db: "admin" }] })
> db.auth("admin", "<senha>")
> exit
```

Editar o arquivo `/etc/mongod.conf` e adicionar as seguintes linhas:
```
security:
  authorization: enabled
```

Reiniciar o serviço do MongoDB:
```
systemctl restart mongod.service
```

## Criar usuário para a base do Graylog:
```
mongo
> use admin
> db.auth("admin", "<senha>")
> use graylog
> db.createUser({ user: "graylog", pwd: "<senha>", roles: [{ role: "dbOwner", db: "graylog" }] })
> db.auth("graylog", "<senha>")
> show collections
> exit
```

## Configurar Graylog para usar autenticação no MongoDB
Editar o arquivo `/etc/graylog/server/server.conf` e alterar o campo `mongodb_uri` para:
```
mongodb_uri = mongodb://graylog:<senha>@localhost:27017/graylog
```

## Configurar Certificado TLS para uso dos coletores e NGINX (Self-signed)

Criar um certificado autoassinado baseado no FQDN do servidor Graylog
```
cd /etc/pki/tls
openssl req -subj '/CN=<graylog-server-fqdn>/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/graylog-server.key -out certs/graylog-server.crt
```

## Habilitar SSL no NGINX

Gerar chave Diffie-Hellman para "Perfect Forward Secrecy"
```
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
```

Alterar o `/etc/nginx/nginx.conf` e ajustar os parâmetros do default server na porta 80 (HTTP):
 - Comentar a linha `include /etc/nginx/default.d/*.conf;`
 - Ajustar o redrect do `location /` para https:
    ```
    location / {
            rewrite     ^ https://<graylog-server-fqdn>$request_uri? permanent;
        }
    ```

Ajustar o default server na porta 443 (HTTPS) no arquivo `/etc/nginx/nginx.conf`:
 - Adicionar os parâmetros de SSL;
 - Adicionar o parâmetro `include /etc/nginx/default.d/*.conf;`
 - Remover a seção `location /`
 - Ajustar os parâmetros `ssl_certificate` e `ssl_certificate_key` utilizando o Certificado TLS gerado anteriormente
 - Ajustar o parâmetro `ssl_dhparam` gerado anteriormente

Exemplo de configuração do SSL:
```
server {
    listen       443 ssl http2 default_server;
    listen       [::]:443 ssl http2 default_server;
    server_name  <graylog-server-fqdn>;
    root         /usr/share/nginx/html;

    ssl on;
    ssl_stapling on;
    ssl_certificate "/etc/pki/tls/certs/graylog-server.crt";
    ssl_certificate_key "/etc/pki/tls/private/graylog-server.key";
    ssl_dhparam         "/etc/ssl/certs/dhparam.pem";
    ssl_trusted_certificate "/etc/pki/tls/certs/graylog-server.crt";
    ssl_ciphers         'kEECDH+ECDSA+AES128 kEECDH+ECDSA+AES256 kEECDH+AES128 kEECDH+AES256 kEDH+AES128 kEDH+AES256 DES-CBC3-SH+SHA !aNULL !eNULL !LOW !kECDH !DSS !MD5 !EXP !PSK !SRP !CAMELLIA !SEED';
    ssl_session_timeout     5m;
    ssl_protocols           TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers   on;
    ssl_session_cache       builtin:1000 shared:SSL:5m;

    # Load configuration files for the default server block.
    include /etc/nginx/default.d/*.conf;

    error_page 404 /404.html;
        location = /40x.html {
    }

    error_page 500 502 503 504 /50x.html;
        location = /50x.html {
    }
}
```
