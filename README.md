# openssl-scripts

## description
scripts to transform hexcode, bignum, openssl struct and so on


## intro

for some reason, I have to frequently access bignum, hexcode, `EVP_PKEY`,  `EC_KEY`, `EC_POINT` in my work. 

Although openssl is convenient to  generate keys, certs and do sign/verify/encrypt/decrypt, it feels hard to use when mentioning transorm in different data indications. 

So I plan to summarize the common scripts used in work(C programming language probably most), and some mistakes I frequently made.


Welcome to join us. （〃｀ 3′〃）