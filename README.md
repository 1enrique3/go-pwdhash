# pwdhash

**pwdhash** is a Go module that allows you to hash passwords using Argon2id.

```go
package main

import (
	"fmt"
	"log"

	"github.com/1enrique3/go-pwdhash/argon2"
)

func main() {
	hash, err := argon2.Default.Hash([]byte("password"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Hash: %s", hash)
}
```