# scalpel

![A scalpel and stitch tool][logo]


### Snip around and sign binaries

This is mostly used for the case where parts of the binary need to be extracted or replaced.



#### Use Cases

* extract Winc firmware from AIO parts for custom update procedures and recovery

```
scalpel --start 0 --size 4096 --output winc_booloader.bin xdk-asf-3.36.2/common/components/wifi/winc1500/firmware_update_project/firmware/firmware/m2m_aio_3a0.bin
scalpel --start 40960 --size 241664 --output winc_part_A.bin xdk-asf-3.36.2/common/components/wifi/winc1500/firmware_update_project/firmware/firmware/m2m_aio_3a0.bin
scalpel --start 282624 --size 241664 --output winc_part_B.bin xdk-asf-3.36.2/common/components/wifi/winc1500/firmware_update_project/firmware/firmware/m2m_aio_3a0.bin
```

#### Features 

- [x] cut off a binary at specific start and end/size
- [x] Add signature verification and appendix features (using preferably [ring] and [webpki] or as an alternative [sodiumoxide] (linking it statically))
- [ ] Handle endianness of checksums properly
- [ ] Replace parts (i.e. cert files or NVStore sections) (with resigning if necessary)
- [ ] Allow hexadecimal input
- [x] Allow multipile input scales (K = 1024, M = 1024*1024)
- [ ] Add verifier option for alignment to given sector/page size


#### Hints

- Use `xxd -i sliced.bin > sliced_binary.hpp` to create a header file out of the result.

- Convert RSA keys in .pem format to pkcs8 format via openssl (see `ring` doc [doc-ring] ), `openssl` supports Ed25519 algorithm currently only on `master` branch

    ```
    openssl pkcs8 -toppk8 -nocrypt -outform der -in [key.pem] > [pkcs8_key.pk8]
    ```

- Generate valid Ed25519 Keypair use small tool from `ring` author:
    ```
    cargo install kt
    kt generate ed25519 --out=FILE
    ```



[logo]: https://github.com/nello-io/scalpel/raw/master/scalpel.jpg "Logo"
[sodiumoxide]: https://docs.rs/sodiumoxide/0.0.16/sodiumoxide/
[ring]: https://crates.io/crates/ring
[webpki]: https://crates.io/crates/webpki
[doc-ring]: https://docs.rs/ring/0.13.0-alpha/ring/signature/struct.RSAKeyPair.html
