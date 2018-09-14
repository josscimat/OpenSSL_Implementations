passphrase="cimat"

openssl genrsa -aes256 -passout pass:$passphrase -out /tmp/private512_v1-5.pem 512
openssl rsa -in /tmp/private512_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public512_v1-5.pem
openssl dgst -sha256 -sign /tmp/private512_v1-5.pem -passin pass:$passphrase -out /tmp/signature512.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public512_v1-5.pem -signature /tmp/signature512.sha256 ./documento.pdf
rm /tmp/signature512.sha256
rm /tmp/private512_v1-5.pem
rm /tmp/public512_v1-5.pem

openssl genrsa -aes128 -passout pass:$passphrase -out /tmp/private1024_v1-5.pem 1024
openssl rsa -in /tmp/private1024_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public1024_v1-5.pem
openssl dgst -sha256 -sign /tmp/private1024_v1-5.pem -passin pass:$passphrase -out /tmp/signature1024.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public1024_v1-5.pem -signature /tmp/signature1024.sha256 ./documento.pdf
rm /tmp/signature1024.sha256
rm /tmp/private1024_v1-5.pem
rm /tmp/public1024_v1-5.pem

openssl genrsa -aes128 -passout pass:$passphrase -out /tmp/private2048_v1-5.pem 2048
openssl rsa -in /tmp/private2048_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public2048_v1-5.pem
openssl dgst -sha256 -sign /tmp/private2048_v1-5.pem -passin pass:$passphrase -out /tmp/signature2048.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public2048_v1-5.pem -signature /tmp/signature2048.sha256 ./documento.pdf
rm /tmp/signature2048.sha256
rm /tmp/private2048_v1-5.pem
rm /tmp/public2048_v1-5.pem

openssl genrsa -aes128 -passout pass:$passphrase -out /tmp/private3072_v1-5.pem 3072
openssl rsa -in /tmp/private3072_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public3072_v1-5.pem
openssl dgst -sha256 -sign /tmp/private3072_v1-5.pem -passin pass:$passphrase -out /tmp/signature3072.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public3072_v1-5.pem -signature /tmp/signature3072.sha256 ./documento.pdf
rm /tmp/signature3072.sha256
rm /tmp/private3072_v1-5.pem
rm /tmp/public3072_v1-5.pem

openssl genrsa -aes128 -passout pass:$passphrase -out /tmp/private4096_v1-5.pem 4096
openssl rsa -in /tmp/private4096_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public4096_v1-5.pem
openssl dgst -sha256 -sign /tmp/private4096_v1-5.pem -passin pass:$passphrase -out /tmp/signature4096.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public4096_v1-5.pem -signature /tmp/signature4096.sha256 ./documento.pdf
rm /tmp/signature4096.sha256
rm /tmp/private4096_v1-5.pem
rm /tmp/public4096_v1-5.pem

openssl genrsa -aes128 -passout pass:$passphrase -out /tmp/private7680_v1-5.pem 7680
openssl rsa -in /tmp/private7680_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public7680_v1-5.pem
openssl dgst -sha256 -sign /tmp/private7680_v1-5.pem -passin pass:$passphrase -out /tmp/signature7680.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public7680_v1-5.pem -signature /tmp/signature7680.sha256 ./documento.pdf
rm /tmp/signature7680.sha256
rm /tmp/private7680_v1-5.pem
rm /tmp/public7680_v1-5.pem

openssl genrsa -aes128 -passout pass:$passphrase -out /tmp/private15360_v1-5.pem 15360
openssl rsa -in /tmp/private15360_v1-5.pem -passin pass:$passphrase -pubout -out /tmp/public15360_v1-5.pem
openssl dgst -sha256 -sign /tmp/private15360_v1-5.pem -passin pass:$passphrase -out /tmp/signature15360.sha256 ./documento.pdf
openssl dgst -sha256 -verify /tmp/public15360_v1-5.pem -signature /tmp/signature15360.sha256 ./documento.pdf
rm /tmp/signature15360.sha256
rm /tmp/private15360_v1-5.pem
rm /tmp/public15360_v1-5.pem






