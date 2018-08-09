# ACG
Deadline: 15 August 2018

## OpenSSL
[OpenSSL Commands](https://www.sslshopper.com/article-most-common-openssl-commands.html)

## Running
```bash
# Recompile client and server and run server
gradle -q && java -jar build/libs/SecureFTP-Server-0.1.jar -c 'src/main/resources/SecureFTP.conf'
# run client
java -jar build/libs/SecureFTP-Client-0.1.jar -s 127.0.0.1 -p 9000 -c src/main/resources/CA.pem
```