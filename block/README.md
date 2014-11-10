# Block

### Problem


> Daedalus Crop has been using this script to encrypt it's data! We think this file contains a password to their command server. Can you crack it?

```python
#!/usr/bin/python2
from sys import argv, exit
import struct

SBoxes = [[15, 1, 7, 0, 9, 6, 2, 14, 11, 8, 5, 3, 12, 13, 4, 10], [3, 7, 8, 9, 11, 0, 15, 13, 4, 1, 10, 2, 14, 6, 12, 5], [4, 12, 9, 8, 5, 13, 11, 7, 6, 3, 10, 14, 15, 1, 2, 0], [2, 4, 10, 5, 7, 13, 1, 15, 0, 11, 3, 12, 14, 9, 8, 6], [3, 8, 0, 2, 13, 14, 5, 11, 9, 1, 7, 12, 4, 6, 10, 15], [14, 12, 7, 0, 11, 4, 13, 15, 10, 3, 8, 9, 2, 6, 1, 5]]

SInvBoxes = [[3, 1, 6, 11, 14, 10, 5, 2, 9, 4, 15, 8, 12, 13, 7, 0], [5, 9, 11, 0, 8, 15, 13, 1, 2, 3, 10, 4, 14, 7, 12, 6], [15, 13, 14, 9, 0, 4, 8, 7, 3, 2, 10, 6, 1, 5, 11, 12], [8, 6, 0, 10, 1, 3, 15, 4, 14, 13, 2, 9, 11, 5, 12, 7], [2, 9, 3, 0, 12, 6, 13, 10, 1, 8, 14, 7, 11, 4, 5, 15], [3, 14, 12, 9, 5, 15, 13, 2, 10, 11, 8, 4, 1, 6, 0, 7]]

def S(block, SBoxes):
    output = 0
    for i in xrange(0, len(SBoxes)):
        output |= SBoxes[i][(block >> 4*i) & 0b1111] << 4*i

    return output


PBox = [13, 3, 15, 23, 6, 5, 22, 21, 19, 1, 18, 17, 20, 10, 7, 8, 12, 2, 16, 9, 14, 0, 11, 4]
PInvBox = [21, 9, 17, 1, 23, 5, 4, 14, 15, 19, 13, 22, 16, 0, 20, 2, 18, 11, 10, 8, 12, 7, 6, 3]
def permute(block, pbox):
    output = 0
    for i in xrange(24):
        bit = (block >> pbox[i]) & 1
        output |= (bit << i)
    return output

def encrypt_data(data, key):
    enc = ""
    for i in xrange(0, len(data), 3):
        block = int(data[i:i+3].encode('hex'), 16)

        for j in xrange(0, 3):
            block ^= key
            block = S(block, SBoxes)
            block = permute(block, PBox)

        block ^= key

        enc += ("%06x" % block).decode('hex')

    return enc

def decrypt_data(data, key):
    dec = ""
    for i in xrange(0, len(data), 3):
        block = int(data[i:i+3].encode('hex'), 16)

        block ^= key
        for j in xrange(0, 3):
            block = permute(block, PInvBox)
            block = S(block, SInvBoxes)
            block ^= key

        dec += ("%06x" % block).decode('hex')

    return dec

def encrypt(data, key1, key2):
    encrypted = encrypt_data(data, key1)
    encrypted = encrypt_data(encrypted, key2)
    return encrypted

def decrypt(data, key1, key2):
    decrypted = decrypt_data(data, key2)
    decrypted = decrypt_data(decrypted, key1)
    return decrypted

def usage():
    print "Usage: %s [encrypt/decrypt] [key1] [key2] [in_file] [out_file]" % argv[0]
    exit(1)

def main():
    if len(argv) != 6:
        usage()

    if len(argv[2]) > 6:
        print "key1 is too large"
    elif len(argv[3]) > 6:
        print "key2 is too large"

    key1 = int(argv[2], 16)
    key2 = int(argv[3], 16)

    in_file = open(argv[4], "r")

    data = ""
    while True:
        read = in_file.read(1024)
        if len(read) == 0:
            break

        data += read

    in_file.close()

    if argv[1] == "encrypt":
        data = "message: " + data
        if len(data) % 3 != 0: #pad
            data += ("\x00" * (3 - (len(data) % 3)))

        output = encrypt(data, key1, key2)
    elif argv[1] == "decrypt":
        output = decrypt(data, key1, key2)
    else:
        usage()


    out_file = open(argv[5], "w")
    out_file.write(output)
    out_file.close()

if __name__ == "__main__":
    main()

```

After a short inspection, I noticed that this script seemed to do some sort of block cipher with a key lenght of 3 bytes. Since the data is encrypted once with key1 and then a second time with key2, it would seem that this increased the keylength the 6 bytes. Unfortuantly the only way to break a cipher like this is through brute forcing and 6 bytes would take too long.

This cipher is vulnerable to a Meet in the Middle attack. This means that in 16**6 times we can break this cipher instead of 16**12. This attack works by encrypting a plain-text with every key in the keyspace and storing those in a table. You then decreypt the matching cipher-text with every possible key until you collide with a vaule in your table.

```python

	

    import block
     
    table = {}
    for key_forward in range(16**6):
        middle_for = block.encrypt_data("message: ", key_forward).encode('hex')
        table[middle_for] = key_forward
        if key_forward % 100000 == 0:
            print key_forward
     
    for key_backward in range(16**6):
        middle_back = block.decrypt_data("\x38\xB3\x89\x25\x3A\x84\x89\x7A\xBD", key_backward).encode('hex')
        if key_backward % 100000 == 0:
            print key_backward
        if middle_back in table:
            print "SOLUTION!!!!"
            print key_backward
            print table[middle_back]



```