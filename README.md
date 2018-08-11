# ACG
Deadline: 15 August 2018

## CA and Server Certificate setup
[OpenSSL Commands](https://www.sslshopper.com/article-most-common-openssl-commands.html)
```bash
# Generate CA encrypted key
openssl genrsa -des3 -out CA.key 4096
# Generate CA cert
openssl req -x509 -new -nodes -key CA.key -sha256 -days 1825 -out CA.crt
# Generate server private key and a csr
openssl req -out server.csr -new -newkey rsa:4096 -nodes -keyout server.key
# Generate server cert with CA
openssl x509 -req -in server.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out server.crt -days 1825 -sha256
# Convert to PKCS#12
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -certfile CA.crt
```
## Server Configuration
[Sample configuration file](src/main/resources/SecureFTP.conf)
```bash
# Address which server listens on
BIND_ADDR=0.0.0.0
# Port which server listens on
PORT=9000
# Key Store Path
KEYSTORE=src/main/resources/server.pfx
# Key Store Password
KEYSTORE_PASS=password
# Alias for cert in keystore
ALIASNAME=1
# Alias Password for alias
ALIAS_PASS=password
# Banner for Secure FTP Server
BANNER=src/main/resources/banner.txt
# Absolute path to Default directory
DEFAULT_DIR=/tmp
# Authorization file path
AUTH_FILE=src/main/resources/auth
```

## Compiling
[Gradle](https://gradle.org/install/) is required for compiling  
Precompiled JAR files are avaliable at [distrib](distrib/) folder
```bash
# Clean and compile the whole project
./gradlew -q
# Compile server
./gradlew server
# Compile client
./gradlew client
# Compile register tool
./gradlew register
```

## Usage
You can pass in `-h` to get the available options for each program.
```bash
# Registering a new user
java -jar SecureFTP-Register-0.1.jar -a -u <username> -p <path to auth file>
# Delete a user
java -jar SecureFTP-Register-0.1.jar -d -u <username> -p <path to auth file>
# Run the server
java -jar SecureFTP-Server-0.1.jar -c <path to conf file>
# run client
java -jar SecureFTP-Client-0.1.jar -s <server IP> -p <server port> -c <path to CA cert>
```

### Sample Usage
```bash
# Registering a new user
java -jar SecureFTP-Register-0.1.jar -a -u <username> -p 'src/main/resources/auth'
# Delete a user
java -jar SecureFTP-Register-0.1.jar -d -u <username> -p 'src/main/resources/auth'
# Run the server
java -jar SecureFTP-Server-0.1.jar -c 'src/main/resources/SecureFTP.conf'
# run client
java -jar SecureFTP-Client-0.1.jar -s 127.0.0.1 -p 9000 -c 'src/main/resources/CA.crt'
```