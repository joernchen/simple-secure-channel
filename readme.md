# Overview
This project aims to implement a cryptographically secure communication channel,
similar to what TLS does up to a certain degree. The distinguishing feature is
that the channel is established based on a shared (potentially even low-entropy)
password. Please note that this implies that no party is required to make use of
public keys to prove their identity. Still, a number of security guarantess can
be made. Most prominently, the key exchange performed in order to establish the
channel is secure against active and passive eavesdroppers. If a low-entropy
password (such as a four-digit PIN) is used, rate-limiting prevents attackers
from brute-force guessing attacks. The channel itself is based on a symmetric
cipher in EAX mode.  EAX mode again provides a number of security guarantess,
which allow to reduce its security to the security of the underlying block
cipher.

# Cryptographic Primitives and Protocols
## Key Exchange
The key exchange is performed using the J-PAKE protocol. J-PAKE can be run on
any structure that allows Diffie-Hellman style key exchange, including elliptic
curves and modp groups. Please refer to https://eprint.iacr.org/2010/190.pdf for
details.

## Secure Channel
The secure channel currently makes use of AES (default) or Twofish
(https://www.schneier.com/paper-twofish-paper.html) in EAX mode
(http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf).

# Design
As already outlined above, the implementation aims to provide security based on
only a shared, potentially low-entropy, password. While this approach hopefully
provides improved convenience over X.509-based approaches (TLS), it also comes
with a number of limitations. First of all, the J-PAKE protocol requires the
shared password to be present in plain text on both sides of the connection.
Secondly, if low-entropy passwords are used, special protection measures have to
be implemented in order to be secure against brute-force attacks.

## Central AAA Service
As passwords have to be present in plain text on both sides of the connection,
this implementation requires using an AAA service. The idea is the following:
a user may have several accounts on several different services (like: a VPN
gateway, a remote shell service, etc.). In order to provide convenience for the
user, the password for all these services should be allowed to be the same.
However, the password should not have to be stored in every service
implementation for obvious reasons. Therefore, a central AAA service is used.
When a user establishes a secure channel with a service, the handshake messages
sent by the user are forwarded to the AAA service, which will perform the
authentication and (if successful) share the master key with the actual service.

## Rate-Limiting
Both ends of the authentication protocol (i.e., the AAA service and the user)
have to make user of rate-limiting in order to prevent brute-force guessing of
passwords. Therefore, a special interface for obtaining user credentials is
used, which introduces an exponential timeout after each failed login attempt.

# Envisioned Use-Cases
## VPN
A VPN service that is solely based on user names and passwords could provide a
convenient experience for both, the user and the administrator. For a small or
medium-sized setup, a full-blown PKI is often considered too complex. Today,
this often leads to shared certificates, missing revocation procedures, expired
certificates and the like. Cryptography based on user names and passwords could
improve this situation.

## Shell
Consider the most wide-spread remote shell protocol: SSH. A common misconception
is that SSH requires the user to remember only their user name and password. In
fact, this is not true. The user also has to remember the host key of the server
system, at least until the first connection is established. Quite often, the
user just accepts any host key. This implementation however would make host-keys
obsolete: authentication succeeds if and only if both sides know the same
password. Therefore, server identity would be implicitly provided by "knowing
the right password". 

# Testing
In order to see the current development status, just clone the repo and say
<pre>
cabal install
</pre>
You can then start the programs accountStore. Upon its first start, it will
tell you the administrator credentials that it automatically generated.
Use accountClient like this in order to set up further accounts:
<pre>
accountClient -h 127.0.0.1 -a addservice -s testService
accountClient -h 127.0.0.1 -a adduser -u userName
accountClient -h 127.0.0.1 -a allowforservice -u userName -s testService
</pre>
The passwords for the services are "test" for testService and "userPass" for
userName.  Now you can use jtunnel and testClient. Start jtunnel and then
testClient. Inside testClient, type:
<pre>
google.com
80
GET / HTTP/1.0


</pre>
and observe that jtunnel transparently tunnels your data through a secure
connection.
