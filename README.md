# goPassword

A very simple password hashing and salting algorthm in go

use
`HashPassword(plaintextPassword String) string`
to hash a password and return the encoded hash. Then
`PasswordCheck(plaintextPassword String, encHash) bool`
to check a password against a hash
