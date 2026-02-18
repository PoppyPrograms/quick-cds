openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -sha256 -days 3650 -nodes -subj "/C=FR/ST=France/L=France/O=PPP/OU=PPP Cloud Engineering/CN=qcds.totocodes.fr"
