# OpenSSL_Implementations

This repository contains some implementations of Digital Signatures of the OpenSSL Library including Crypto implementations and Envelope (EVP) implementations, OpenSSL MAN pages recomends always use EVP libraries unless you develop some low level implementation.

In the C folder you will find the implementations for Digital Signatures; starting with the EVP series; keygen implementation means Keys Generation and digest means Hash function in this case the SHA1 variant, the implementations for RSA signature are the PKCS#1v1.5 and PKCS#1v2.2, the original implementation of both comes in 2 versions, the first version is without validations (more fast) and the second implementation with validations (error proof); the bench implementations comes in 3 variants, the first version is without validations and one time execution (more fast), the second version comes with validations (error proof) and one time execution and finaly the third version comes without validations (more fast) with 10000 cicle execution to obtain the average and more real value; the p versions stands for primivite versions of primitive cryptographic functions, this implementations are not recomended to use unless you know what are you doing.

This project is far from over, I will include in the future other signature implementations like DSA and ECDSA stay tunned for more...

If you have any questions or recomendations regarding the implementations feel free to contact me to: jose.rodriguez@cimat.mx

This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
