# Image Steganography Tool

Simple C++ **Encryption** and **Steganography** tool that uses Password-Protected-Encryption to secure a file's contents, and then proceeds to embed it 
insde an image's pixel-data using Least-Significant-Bit encoding. For Linux, MacOS, and Windows systems.

## Encoding

```
$ ./steganography encode -i data/orig.png -e data/jekyll_and_hyde.zip -o output.png
Password: 1234
* Image size: 640x426 pixels
* Encoding level: Low (Default)
* Max embed size: 132.38 KiB
* Embed size: 61.77 KiB
* Encrypted embed size: 61.78 KiB
* Generated CRC32 checksum
* Generated encryption key with PBKDF2-HMAC-SHA-256 (20000 rounds)
* Encrypted embed with AES-256-CBC
* Embedded jekyll_and_hyde.zip into image
* Sucessfully wrote to output.png
```

Original image:

![Original image](data/orig.png)

Image with embedded ZIP containg the entire contents of the book "Dr Jekyll and Mr Hyde":

![Image with embed](data/output.png)

## Decoding

```
$ ./steganography decode -i output.png -o "out - jekyll_and_hyde.zip"
Password: 1234
* Image size: 640x426 pixels
* Generated decryption key with PBKDF2-HMAC-SHA-256 (20000 rounds)
* Sucessfully decrypted header
* File signatures match
* Detected embed jekyll_and_hyde.zip
* Encoding level: Low (Default)
* Encrypted embed size: 61.78 KiB
* Successfully decrypted the embed
* Decrypted embed size: 61.77 KiB
* CRC32 checksum matches
* Successfully wrote to out - jekyll_and_hyde.zip
```

## Building

```
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ make -j 4
```

## Usage

```
Usage: steganography [-h] {decode,encode}

Optional arguments:
  -h, --help   	shows help message and exits
  -v, --version	prints version information and exits

Subcommands:
  decode        Decodes and extracts an embed-file from an image
  encode        Encodes an embed-file into an image
```

### Encoding

```
Usage: encode [-h] --input VAR --output VAR --embed VAR [--passwd VAR]

Encodes an embed-file into an image

Optional arguments:
  -h, --help   	shows help message and exits
  -v, --version	prints version information and exits
  -i, --input  	specify the input image. [required]
  -o, --output 	specify the output image. [required]
  -e, --embed  	specify the file to embed. [required]
  -p, --passwd 	specify the encryption password.
```

### Decoding

```
Usage: decode [-h] --input VAR [--output VAR] [--passwd VAR]

Decodes and extracts an embed-file from an image

Optional arguments:
  -h, --help   	shows help message and exits
  -v, --version	prints version information and exits
  -i, --input  	specify the input image. [required]
  -o, --output 	specify the output file. [default: ""]
  -p, --passwd 	specify the encryption password.
```

## Theory Of Operation

### Encoding

The program operates by first randomly generating a *128-bit Password Salt* and a *128-bit AES Initialization Vector* by reading binary data from **/dev/urandom**.
It then uses that *Password Salt* as a parameter in generating an encryption key, by using **PBKDF2-HMAC-SHA-256** on a user inputted string.
A **CRC32** hash of the file to embed is then calculated, and stored in the header to act as a checksum for the validity of the data.
It then pads the binary data of the file to embed using the **PKCS #7** algorithm, followed by actually encrypting both the header and
the padded data, with **AES-256** in **CBC Mode**, using the previously generated *Initialization Vector*.
Now the data is actually encoded inside the image by first picking a random offset, and then going through each bit of data and storing it 
inside the actual image pixel data, which it accomplishes by setting the *Least-Significant-Bit* of each channel byte of each pixel.

### Decoding

The decoding process works exactly the same as the encoding process previously described above, just in reverse. 
The only difference is that for decoding, after the program attempts to extract and decrypt the data, it compares some of the information in the header section 
in an attempt to validate the extraction process. The header fields which are compared are: The 4 byte file signature custom to this program, and the 
**CRC32** hash of the decrypted data. 
If any of these fields do not match to their correct values, the decryption process will fail. This should only happen if the file which you were attempting to 
decrypt does not actually contain an embed, if the password you entered is wrong, or if the image file was somehow corrupted.

### Detection

While the detection of data being embedded in an image is a trivial task, theoretically there is no way of knowing that it was this program that did it, and theoretically
there should be no known way to decrypt the data without knowing the password, that is without spending millions of years in the process of doing so.

## Disclaimer

Do not use this program to encrypt and hide important data which you wish to keep away from prying eyes. This is just a simple proof-of-concept program that I made for fun.
I'm no cryptographer. I'm just a hobbyist, use at your own risk.

## Copyright

This software is licensed under MIT. Copyright © 2022 Zach Collins
