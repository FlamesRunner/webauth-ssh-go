# webauth-ssh-go
An implementation of asymmetric, fully distributed secure side-channel authentication for web applications using SSH and Go.

Live demo [here](https://demo.devhub.club/).

## Notes

This demo takes the same public key format as your OpenSSH authorized_keys file
and the *.pub file OpenSSH generates for a keypair (see OpenSSH sshd(8) manual page).

It supports SSH-RSA, SSH-DSA, ECDSA-SHA2-NISTP{256,384,521}.
The server itself currently offers a RSA key, length 4096 bit with fingerprint:
SHA256:IW0JCfRu0QMiR5ffaQQmnEGzXMe3lgtq524wahMFXo8.

Inspired by [@altitude](https://github.com/altitude/login-with-ssh/).

## Implementation
Implemented in pure [go](http://golang.org), working without Javascript in the demo.
The web application generates a unique token corresponding to the user session and the public key that should be used.
The public key is then parsed and checked for correctness.
If everything worked, the user is then able to access the ssh side-channel as instructed.
Upon connection of a client over ssh, the application only validates the public key your client offers with your token, registers the authentication callback and finally hangs up on the connection with a "Auth request received." message.
If you try to use a wrong token or an unregistered public key you will receive "Permission denied (publickey)." as response.

## Extension
- Support Ed25519 (not supported in golang.org/x/crypto/ssh at the moment)
- Special browser plugins supporting authentication (true random numbers are currently only possible in chrome context)
