# decrypt_sp

tool for decrypting and encrypting prx.enc

## credits

SSL for encript code

mathieulh for original psp code

## usage

grab `msid.bin` using [**MSID-Dumper-3.XX-MOD**](https://github.com/ErikPshat/MSID-Dumper-3.XX-MOD) by ![репозиторий ErikPshat](https://avatars1.githubusercontent.com/u/1283017?s=35&v=4)

place `msid.bin` to jigkick and 'prx' folder with prx.enc files and run command:

```
./decrypt_sp -d
```

will generate 'dec' folder with decrypted files

place `msid.bin` from your own memstick and run command:

```
./decrypt_sp -e
```

will generate 'enc' folder with encrypted files for your memstick

rename 'enc' folder to 'prx' - done
