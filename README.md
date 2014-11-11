Rainbow Table
============
Rainbow Table implementation in C that cracks up to 32 bit hashes with the hash h(k) = AES(0), where k is the AES key. 

Run with:
gentable n s
Where n is the number of bits in the key, and s is a chainlength factor. 

Crack a given hash with
crack n s hash
Where hash is given in hex, with 0x prefix. 