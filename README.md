# Remote Surveillance Platform

A client-server application for collecting information from the client including keyboard output and screenshots, in addition to injecting commands into the client's computer.
Key points in the application:

- The server is multi-client.
- All communication is end-to-end encrypted by AES128 when establishing the conversation between the server and the client according to Diffie-Hellman key exchange when each client receives a different public key from the server.
- The data traffic between the client and the server is divided into packets in order not to overload the client's bandwidth and not to arouse suspicion.

## Features

- Every communication with each client is kept in a separate folder according to the client number.
- Each client's keyboard action is saved in a folder in the format: (time: input) inside a "KeyLog.txt" file with an update every 10 seconds.
- Every 10 seconds a screenshot of the client's computer is saved.
- All the commands that the server sends to the client (reverse shell) are saved in the file "client_shell.txt" including the responses that the client returns.

## Examples

An example of running on the server side:

```sh
SERVER: starting up on 192.168.3.17 port 8822
SERVER: waiting for a connection

SERVER: Client connected from ('192.168.3.133', 59208)
SERVER: client is now concentering:  59208

SERVER: Enter command:
ping 8.8.8.8

SERVER: clients:  ['59208']
SERVER: Enter client address:
59208

SERVER: REVERSE_SHELL:
Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
```

An example of keyboard tracking from a client:

```sh
24/01/2023 23:15:58 my name is Dani
24/01/2023 23:16:08 my password is 1234
24/01/2023 23:16:18
```

Additional examples including screenshots are in the repo in the examples folder.

## License

MIT
