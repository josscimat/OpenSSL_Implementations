passphrase="cimat"

openssl genrsa -aes256 -passout pass:$passphrase -out /tmp/private512_v1-5.pem 512
openssl rsa -in /tmp/private512_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public512_v1-5.pem
openssl rsautl -sha256 -sign /tmp/private512_v1-5.pem -passin pass:$passphrase -out /tmp/signature512.sha256 ./documento.pdf
openssl rsautl -sha256 -verify /tmp/public512_v1-5.pem -signature /tmp/signature512.sha256 ./documento.pdf
rm /tmp/signature512.sha256
rm /tmp/private512_v1-5.pem
rm /tmp/public512_v1-5.pem
