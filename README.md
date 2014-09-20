# Nyms Mail Verifier

The email verifier is a component in the Nyms key directory system which performs an email verification protocol with users of the system to demonstrate that a user who is possession of a certain PGP private key also controls the email address associated with it.

The mail verifier is simple and stateless and doesn't attempt to verify the identity claim made by the user.  What it does is process incoming email sent to the configured verification mail address, and returns a signed message containing the original mail and some extra information about the transaction.

The mail returned by the verification service contains an attachment which is a Gzip Tar archive containing the following list of files:

1. **message** The exact original message received by the service
2. **mx** The MX records retrieved to send the response
3. **dkim** If the original message contained a DKIM signature, the corresponding DKIM public key information as retrieved from DNS
4. **certs** The entire TLS certificate chain (in PEM) sent from the destination SMTP server upon connection to transmit the response
5. **timestamp** Unix epoch timestamp at which the transaction was processed as ascii decimal string




