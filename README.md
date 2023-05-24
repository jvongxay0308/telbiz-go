# Telbiz Client Libraries for Go

This repository contains the open-source Go client libraries for Telbiz. These libraries are not officially supported by Telbiz. They are maintained by @jvonxay0308.

## Documentation

The documentation for the Telbiz API can be found [api-docs](https://telbiz.la/pages/doc/user-guide).

## Installation

Use go get to retrieve the latest version of the client.

```bash
go get -u github.com/jvonxay0308/telbiz-go
```

## Usage

```go
import telbiz "github.com/jvonxay0308/telbiz-go"
```

Construct a new Telbiz client, then use the various services on the client to
access different parts of the Telbiz API. For example:

```go
ctx := context.Background()
client, err := telbiz.NewClient(ctx, "YOUR_API_KEY", "YOUR_SECRET_KEY")
if err != nil {
    panic(err)
}
```

Send SMS

```go
message := &telbiz.Message{
    To:    "2077805085",
    Title: telbiz.Info,
    Body:  "This is an open source Tizbiz Client Library for Go develop by jvonxay0308!",
}
sms, err := client.SendSMS(ctx, message)
if err != nil {
    panic(err)
}
```

## Go Versions Supported

This library supports the following Go implementations:

- Go 1.20.x

## Contributing

Contributions are welcome. Please open up an issue or create PR if you would like to help out.
