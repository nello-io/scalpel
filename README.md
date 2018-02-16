# scalpel

![A scalpel][logo]


### Snip around binaries

This is mostly used for the case where parts of the binary need to be extracted or replaced.



#### Use Cases:

* extract Winc firmware from AIO parts for custom update procedures and recovery


#### Features:

* cut off a binary at specific start and end/size


#### ToDo:

* Add Signatue
* Replace parts (i.e. cert files or NVStore sections)
* 


#### Hints

Use `xxd -i sliced.bin > sliced_binary.hpp` to create a header file out of the result.



[logo]: https://github.com/nello-io/scalpel/raw/master/scalpel.jpg "Logo"