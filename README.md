# Secure file transfer

A demonstration for secure file transfer within an organization for CSN-503 course project.

## Implementation
The files are secured using RSA to encrypt and decrypt messages. The architecture used is:

![Screenshot from 2020-11-18 02-28-20](https://user-images.githubusercontent.com/32809272/99504709-e7c93d00-29a5-11eb-9bf8-5c1ae6e9f483.png)

- *Auth server* acts as a registry for active users. It provides root certificate as trust anchor with the network.
It uses its cert to sign authenticated user's public key in a certificate.
- *Clients* Clients listen on ports for incoming connections and handle them using message handlers. Identity of a 
requester is established using the cert provided by them. Cert chain is validated to establish the authenticity and
prevent MITM attacks.
- *Handshake* Our implementation defines and uses a 2-way handshake implemented over TCP handshake wherein both the 
parties exchange their cert so as to establish trust and authenticity.

# References:
- https://medium.com/mobile-development-group/trust-tls-ssl-and-https-b925ac9d59