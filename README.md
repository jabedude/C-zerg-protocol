Codec

- [x] Flourish: man(1) page for decode(1) and encode(1).
- [x] Flourish: GPS output prints Degrees - Minutes - Seconds (DMS)

# Building
```
$ make
```
# Cleaning
```
$ make clean
```
# Build Debug
```
$ make debug
```

# Usage

## Decoder:
```
$ ./bin/decode hello.pcap
*** Packet 1 ***
Version : 1
Sequence : 81
From : 7890
To : 1234
Message : Hello World!
```
## Encode:
```
$ cat > example.txt << EOF
>*** Packet 1 ***
>Version : 1
>Sequence : 81
>From : 7890
>To : 1234
>Message : Hello World!

$ ./bin/encode example.txt hello.pcap
```
