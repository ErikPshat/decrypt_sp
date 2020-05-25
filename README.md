# decrypt_sp

tool for decrypting and encrypting prx.enc

## credits

SSL for encript code

[mathieulh](https://github.com/mathieulh/PRX.ENC-Tool) for original PSP code

[zecoxao](https://github.com/zecoxao/decrypt_sp) for PC port

## usage

1. Grab `msid.bin` using [**MSID-Dumper-3.XX-MOD**](https://github.com/ErikPshat/MSID-Dumper-3.XX-MOD) by ![репозиторий ErikPshat](https://avatars1.githubusercontent.com/u/1283017?s=35&v=4)

2. Place `msid.bin` to jigkick and 'prx' folder with prx.enc files and run command:

```
./decrypt_sp -d
```

3. Will generate 'dec' folder with decrypted files

4. Place `msid.bin` from your own memstick and run command:

```
./decrypt_sp -e
```

5. Will generate 'enc' folder with encrypted files for your memstick

6. Rename 'enc' folder to 'prx' - done
