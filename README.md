# gosrs
gosrs- Sender Rewriting Scheme (SRS) library for Go

**gosrs** is an implementation of the [Sender Rewriting Scheme (SRS)](https://en.wikipedia.org/wiki/Sender_Rewriting_Scheme) in Go, based on the [original SRS paper](http://www.libsrs2.org/srs/srs.pdf), and taking inspiration from the [srslib](https://github.com/jichu4n/srslib) Python implementation.

Highlights:

* No external dependencies
* Implements the standard "Guarded" SRS scheme as described in the [original SRS paper](http://www.libsrs2.org/srs/srs.pdf);
* Simple to use and understand.

## Installation
```
go get  "github.com/daliand/gosrs"
```

## Example Usage

Basic usage 
```
import "github.com/daliand/gosrs"

// Setup Package
srs, err := gosrs.GuardedScheme("MyVerySecretKey")
if err != nil {
    os.Panic(err.Error())
}

// Forward rewrite
fwdAddr := srs.Forward("bob@example.com", "forward.com")
fmt.Printf("SRS Forward address: %s", fwdAddr)


// Reverse revrite
revAddr := srs.Reverse(fwdAddr)
fmt.Printf("Reversed address: %s", revAddr)
```

## License

Licensed under the Apache License, Version 2.0.
