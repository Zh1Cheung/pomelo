# pomelo
A tool of authenticated and encrypted API tokens

# Example


```
package main

import (
   "fmt"
   "github.com/zh1cheung/pomelo"
)

func main() {
   p := pomelo.NewBranca("supersecretkeyyoushouldnotcommit") // This key must be exactly 32 bytes long.
   
   // Encode String to Pomelo Token.
   token, err := p.EncodeToString("Hello world!")
   if err != nil {
      fmt.Println(err)
   }
            
    //p.SetTTL(3600) // Uncomment this to set an expiration (or ttl) of the token (in seconds).
    //token = "87y8daMzSkn7PA7JsvrTT0JUq1OhCjw9K8w2eyY99DKru9FrVKMfeXWW8yB42C7u0I6jNhOdL5ZqL" // This token will be not allowed if a ttl is set.
   
   // Decode Pomelo Token.
   message, err := p.DecodeToString(token)
   if err != nil {
      fmt.Println(err) // token is expired.
      return
   }
   fmt.Println(token) // 87y8da....
   fmt.Println(message) // Hello world!
}
```

