# Project3
JWKS Server
Implements a JWKS (JSON Web Key Set) server with enhanced security features. It uses AES encryption for private keys, provides user registration capabilities,
logs authentication requests, and optionally introduces a rate limiter to control request frequency.

Features:
AES Encryption: Private keys are encrypted using AES encryption for security.
User Registration: Users can register with the server, and their passwords are securely hashed using Argon2.
Authentication Logging: Authentication requests are logged, including the request IP address and timestamp.
Rate Limiter (Optional): Requests to the authentication endpoint are limited to prevent abuse and potential DoS attacks.
Setup:
Clone this repository. 
Set the environment variable NOT_MY_KEY to a secure key for AES encryption.
Run the application using python3 project.py.
Usage:
Register a new user: Send a POST request to /register with JSON data containing the username and email.
Authenticate a user: Send a POST request to /auth with JSON data containing the username and password.
