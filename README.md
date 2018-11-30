# OpenSSL_Implementations

This repository contains some implementations of Digital Signatures of the OpenSSL Library including Crypto implementations and Envelope (EVP) implementations, OpenSSL MAN pages recomends always use EVP libraries unless you develop some low level implementation.

In the BASH folder I include 2 examples on the RSA Digital signatures with the variants of PKCS#1v1.5 and PKCS#1v2.2, I include the certificates only for testing purposes, this will never be used on real implementations. 

In the C folder you will find the implementations for Digital Signatures; starting with the EVP series; keygen implementation means Keys Generation and digest means Hash function in this case the SHA1 variant, the implementations for RSA signature are the PKCS#1v1.5 and PKCS#1v2.2, the original implementation of both comes in 2 versions, the first version is without validations (more fast) and the second implementation with validations (error proof); the bench implementations comes in 3 variants, the first version is without validations and one time execution (more fast), the second version comes with validations (error proof) and one time execution and finaly the third version comes without validations (more fast) with 10000 cicle execution to obtain the average and a more real value; the p versions stands for primivite versions of primitive cryptographic functions, this implementations are not recomended to use unless you know what are you doing.

This project is far from over, I will include in the future other signature implementations like DSA and ECDSA and the benchmarks (clock cycles) of all the digital signatures stay tunned for more...

If you have any questions, recomendations or corrections regarding the implementations feel free to contact me to: jose.rodriguez@cimat.mx

This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.

Next I include a table with the results of measuring the digital signature algorithms; it includes the RSA versions 1.5 and 2.2, DSA and ECDSA, RSA version 2.2 comes with SHA256 all left with the SHA1 algorithm, all signatures were tested 10000 cycles and averaging the results, the hardware used was an Intel Core i7 4000 series with 4.0 GHZ speed with no TurboBoost activated; the text in bold are the quickest in the same category with equal lenght keys.

|	**Size Key Bits**	|	**Signature Name**	|	**Signature Clock Cycles**	|	**Signature Time Seconds**	|	**Verification Clock Cycles**	|	**Verification Time Seconds**	|
|	---	|	---	|	---	|	---	|	---	|	---	|
|	163	|	ECDSA_sec163k1	|	**1089790**	|	**0.000272**	|	**2174745**	|	**0.000544**	|
|	163	|	ECDSA_sec163r2	|	1243345	|	0.000311	|	2477345	|	0.000619	|
|	192	|	ECDSA_prime192v1	|	**961336**	|	**0.000240**	|	**876500**	|	**0.000219**	|
|	224	|	ECDSA_secp224r1	|	**2800692**	|	**0.000700**	|	**2360116**	|	**0.000590**	|
|	233	|	ECDSA_sec233r1	|	**1499635**	|	**0.000375**	|	**2930005**	|	**0.000733**	|
|	233	|	ECDSA_sec233k1	|	1557045	|	0.000389	|	3058320	|	0.000765	|
|	256	|	ECDSA_prime256v1	|	**116304**	|	**0.000029**	|	**353872**	|	**0.000088**	|
|	283	|	ECDSA_sec283k1	|	**2756005**	|	**0.000689**	|	**5375475**	|	**0.001344**	|
|	283	|	ECDSA_sec283r1	|	2783855	|	0.000696	|	5593895	|	0.001398	|
|	384	|	ECDSA_secp384r1	|	**4216632**	|	**0.001054**	|	**3275324**	|	**0.000819**	|
|	409	|	ECDSA_sec409k1	|	**4392610**	|	**0.001098**	|	**8738375**	|	**0.002185**	|
|	409	|	ECDSA_sec409r1	|	4678180	|	0.001170	|	9087685	|	0.002272	|
|	512	|	RSA1.5_512	|	**216195**	|	**0.000054**	|	**21055**	|	**0.000005**	|
|	512	|	RSA2.2_512	|	220955	|	0.000055	|	25125	|	0.000006	|
|	512	|	DSA_512	|	237705	|	0.000059	|	144544	|	0.000036	|
|	521	|	ECDSA_secp521r1	|	**10914350**	|	**0.002729**	|	**7309250**	|	**0.001827**	|
|	571	|	ECDSA_sec571k1	|	**11419236**	|	**0.002855**	|	22024986	|	0.005506	|
|	571	|	ECDSA_sec571r1	|	11505815	|	0.002876	|	**21956915**	|	**0.005489**	|
|	1024	|	DSA_1024	|	**486954**	|	**0.000122**	|	356984	|	0.000089	|
|	1024	|	RSA2.2_1024	|	577370	|	0.000144	|	48790	|	0.000012	|
|	1024	|	RSA1.5_1024	|	583745	|	0.000146	|	**45455**	|	**0.000011**	|
|	2048	|	DSA_2048	|	**1278986**	|	**0.000320**	|	1165440	|	0.000291	|
|	2048	|	RSA2.2_2048	|	3033910	|	0.000758	|	171410	|	0.000043	|
|	2048	|	RSA1.5_2048	|	3133288	|	0.000783	|	**149508**	|	**0.000037**	|
|	3072	|	RSA1.5_3072	|	**13339755**	|	**0.003335**	|	**278995**	|	**0.000070**	|
|	3072	|	RSA2.2_3072	|	13856765	|	0.003464	|	291845	|	0.000073	|
|	4096	|	RSA1.5_4096	|	**30902285**	|	**0.007726**	|	**474770**	|	**0.000119**	|
|	4096	|	RSA2.2_4096	|	30982280	|	0.007746	|	497820	|	0.000124	|
|	7680	|	RSA1.5_7680	|	**268500823**	|	**0.067125**	|	**1790554**	|	**0.000448**	|
|	7680	|	RSA2.2_7680	|	288491795	|	0.072123	|	1920852	|	0.000480	|
|	15360	|	RSA2.2_15360	|	**1498892245**	|	**0.374723**	|	6321415	|	0.001580	|
|	15360	|	RSA1.5_15360	|	1548275170	|	0.387069	|	**6247540**	|	**0.001562**	|
