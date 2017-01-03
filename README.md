# skis
A Simple Key Server

Draft version uses sqlite for storage of keys.

Keys are encrypted using a system key which itself is encrypted using a server key. The server key must be set as the environment variable SVR_KEY.

Tokens are encrypted using a token key which is also encrypted using the server key.

Tokens contain another key (randomly generated) and the hashed combination of this key and the system key (above) is used to encrypt the real protected key of concern.
In this way both the system key and the token key are needed to decrypt the protected key stored in the database.

Tokens are not stored in the key-server and need to be deployed to clients once created.

Keys can be created (or added if you've an existing key value) using the API.

API documentation to come...
