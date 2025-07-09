# Motoko JWT

[![MOPS](https://img.shields.io/badge/MOPS-jwt-blue)](https://mops.one/jwt)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/yourusername/motoko_jwt/blob/main/LICENSE)

A Motoko implementation of JSON Web Tokens (JWT) for encoding, decoding, and validation.

## Package

### MOPS

```bash
mops add jwt
```

To set up MOPS package manager, follow the instructions from the [MOPS Site](https://mops.one)

## Supported JWT Features

- Token parsing and validation
- Token serialization to text and binary formats
- Standard JWT claims (iss, sub, aud, exp, nbf, iat, jti)
- Signature verification algorithms:
  - HMAC with SHA-256 (HS256)
  - ECDSA with SHA-256 (ES256, ES256K)
- Validation options for:
  - Token expiration
  - Token validity period (not before)
  - Token issuer
  - Token audience
  - Token signature

## Quick Start

### Example 1: Parse, Validate, and Access Token Data

```motoko
import JWT "mo:jwt";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";

// Parse a JWT string
let jwtString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

switch (JWT.parse(jwtString)) {
    case (#err(msg)) {
        Debug.print("Error parsing JWT: " # msg);
    };
    case (#ok(token)) {
        Debug.print("JWT successfully parsed!");

        // Validate the token
        let validationOptions : JWT.ValidationOptions = {
            expiration = true;  // Check token expiration
            notBefore = true;   // Check token validity start time
            issuer = #skip;     // Skip issuer validation
            audience = #skip;   // Skip audience validation
            signature = #symmetric(Blob.fromArray([/* Secret key bytes */]));  // Validate signature
        };

        switch (JWT.validate(token, validationOptions)) {
            case (#err(msg)) {
                Debug.print("Token validation failed: " # msg);
            };
            case (#ok()) {
                Debug.print("Token is valid!");

                // Access header values
                switch (JWT.getHeaderValue(token, "alg")) {
                    case (?#string(alg)) Debug.print("Algorithm: " # alg);
                    case (_) {};
                };

                // Access payload values
                switch (JWT.getPayloadValue(token, "sub")) {
                    case (?#string(sub)) Debug.print("Subject: " # sub);
                    case (_) {};
                };
            };
        };
    };
};
```

### Example 2: Working with Standard Header and Payload

```motoko
import JWT "mo:jwt";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Float "mo:base/Float";

// Assuming we have a validated token
let token : JWT.Token = /* previously validated token */;

// Get standard header information
switch (JWT.parseStandardHeader(token.header)) {
    case (#err(msg)) {
        Debug.print("Error parsing standard header: " # msg);
    };
    case (#ok(header)) {
        Debug.print("Algorithm: " # header.alg);

        switch (header.typ) {
            case (?typ) Debug.print("Token type: " # typ);
            case (null) {};
        };

        switch (header.kid) {
            case (?kid) Debug.print("Key ID: " # kid);
            case (null) {};
        };
    };
};

// Get standard payload claims
switch (JWT.parseStandardPayload(token.payload)) {
    case (#err(msg)) {
        Debug.print("Error parsing standard payload: " # msg);
    };
    case (#ok(payload)) {
        switch (payload.iss) {
            case (?iss) Debug.print("Issuer: " # iss);
            case (null) {};
        };

        switch (payload.sub) {
            case (?sub) Debug.print("Subject: " # sub);
            case (null) {};
        };

        switch (payload.exp) {
            case (?exp) Debug.print("Expires at: " # Float.toText(exp));
            case (null) {};
        };
    };
};
```

### Example 3: Token Serialization and Signing

```motoko
import JWT "mo:jwt";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Json "mo:json";
import Blob "mo:base/Blob";

// Create an unsigned token
let unsignedToken : JWT.UnsignedToken = {
    header = [
        ("alg", #string("HS256")),
        ("typ", #string("JWT"))
    ];
    payload = [
        ("sub", #string("1234567890")),
        ("name", #string("John Doe")),
        ("iat", #number(#int(1516239022)))
    ];
};

// Convert unsigned token to binary representation
let unsignedBlob = JWT.toBlobUnsigned(unsignedToken);

let signature = sign(unsignedBlob); // Your own signature generator from bytes

let signedToken : JWT.Token = {
    unsignedToken with
    signature = {
        algorithm = "HS256";
        value = signature;
        message = unsignedBlob;
    };
};

// Convert complete token to text (header.payload.signature format)
let completeText = JWT.toText(signedToken);
Debug.print("Complete token: " # completeText);
```

## API Reference

### Types

```motoko
// Unsigned JWT Token (before signing)
public type UnsignedToken = {
    header : [(Text, Json.Json)];
    payload : [(Text, Json.Json)];
};

// Complete JWT Token
public type Token = {
    header : [(Text, Json.Json)];
    payload : [(Text, Json.Json)];
    signature : SignatureInfo;
};

public type SignatureInfo = {
    algorithm : Text;
    value : Blob;
    message : Blob;
};

public type ValidationOptions = {
    expiration : Bool;
    notBefore : Bool;
    issuer : IssuerValidationKind;
    signature : SignatureValidationKind;
    audience : AudienceValidationKind;
};

public type AudienceValidationKind = {
    #skip;
    #one : Text;
    #any : [Text];
    #all : [Text];
};

public type IssuerValidationKind = {
    #skip;
    #one : Text;
    #any : [Text];
};

public type SignatureValidationKind = {
    #skip;
    #key : SignatureVerificationKey;
    #keys : [SignatureVerificationKey];
    #resolver : (issuer : ?Text) -> Iter.Iter<SignatureVerificationKey>;
};

public type SignatureVerificationKeyKind = {
    #symmetric;
    #ecdsa;
};

public type SignatureVerificationKey = {
    #symmetric : Blob;
    #ecdsa : ECDSA.PublicKey;
};

public type StandardHeader = {
    // Required field
    alg : Text; // Algorithm (required by JWT spec)

    // Common optional header fields
    typ : ?Text; // Token type (usually "JWT")
    cty : ?Text; // Content type
    kid : ?Text; // Key ID
    x5c : ?[Text]; // x.509 Certificate Chain
    x5u : ?Text; // x.509 Certificate Chain URL
    crit : ?[Text]; // Critical headers
};

public type StandardPayload = {
    // Standard claims
    iss : ?Text; // Issuer
    sub : ?Text; // Subject
    aud : ?[Text]; // Audience (can be string or array)
    exp : ?Float; // Expiration Time (seconds since epoch)
    nbf : ?Float; // Not Before (seconds since epoch)
    iat : ?Float; // Issued at (seconds since epoch)
    jti : ?Text; // JWT ID
};
```

### Functions

```motoko
// Parse a JWT string into a Token
public func parse(jwt : Text) : Result.Result<Token, Text>;

// Get a value from the token header
public func getHeaderValue(token : Token, key : Text) : ?Json.Json;

// Get a value from the token payload
public func getPayloadValue(token : Token, key : Text) : ?Json.Json;

// Parse header fields into a StandardHeader structure
public func parseStandardHeader(headerFields : [(Text, Json.Json)]) : Result.Result<StandardHeader, Text>;

// Parse payload fields into a StandardPayload structure
public func parseStandardPayload(payloadFields : [(Text, Json.Json)]) : Result.Result<StandardPayload, Text>;

// Validate a token against provided options
public func validate(token : Token, options : ValidationOptions) : Result.Result<(), Text>;

// Convert a complete JWT token to its text representation
public func toText(token : Token) : Text;

// Convert an unsigned JWT token to its text representation (without signature)
public func toTextUnsigned(token : UnsignedToken) : Text;

// Convert a complete JWT token to its binary representation
public func toBlob(token : Token) : Blob;

// Convert an unsigned JWT token to its binary representation (without signature)
public func toBlobUnsigned(token : UnsignedToken) : Blob;
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
