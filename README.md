# Image Steganography Tool

Simple C++ Steganography tool that first encrypts files using AES, and then proceeds to hide them 
insde images using Least-Significant-Bit encoding.

## Encoding

```
$ ./steganography encode data/orig.png data/jekyll_and_hyde.zip
Password: 1234
* Image size: 640x426 pixels
* Encoding level: Low (Default)
* Max embed size: 132.38 KiB
* Embed size: 61.77 KiB
* Encrypted embed size: 61.78 KiB
* Generated CRC32 checksum
* Generated encryption key with PBKDF2-HMAC-SHA-256 (20000 rounds)
* Encrypted embed with AES-256-CBC
* Embeded jekyll_and_hyde.zip into image
* Sucessfully wrote to output.png
```

Original image:

![Original image](/data/orig.png)

Image with embedded ZIP containg the entire contents of the book "Dr Jekyll and Mr Hyde":

![Image with embed](/data/output.png)

## Decoding

```
$ ./steganography decode output.png
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
Successfully wrote to out - jekyll_and_hyde.zip
```

## Building

## Usage

## Theory Of Operation

## Copyright

This software is licensed under MIT. Copyright © 2022 Zach Collins
