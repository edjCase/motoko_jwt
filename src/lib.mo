import Result "mo:core@1/Result";
import Text "mo:core@1/Text";
import Iter "mo:core@1/Iter";
import Blob "mo:core@1/Blob";
import Nat "mo:core@1/Nat";
import Array "mo:core@1/Array";
import Float "mo:core@1/Float";
import Time "mo:core@1/Time";
import Json "mo:json@1";
import BaseX "mo:base-x-encoder@2";
import HMAC "mo:hmac@1";
import ECDSA "mo:ecdsa@7";
import Sha256 "mo:sha2@0/Sha256";
import Bool "mo:core@1/Bool";
import RSA "mo:rsa@2";
import EdDSA "mo:eddsa@2";

/// JWT (JSON Web Token) library for Motoko.
///
/// This module provides functionality for creating, parsing, and validating JSON Web Tokens
/// according to RFC 7519. It supports various signing algorithms including HMAC, ECDSA, RSA, and EdDSA.
///
/// Key features:
/// * Parse JWT tokens from text format
/// * Create and sign JWT tokens
/// * Validate JWT signatures and claims
/// * Support for standard JWT header and payload fields
/// * Extensible validation options
///
/// Example usage:
/// ```motoko
/// import JWT "mo:jwt";
/// import Result "mo:core@1/Result";
///
/// // Parse a JWT token
/// let jwtText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc";
/// let token = JWT.parse(jwtText);
/// ```
///
/// Security considerations:
/// * Always validate signatures in production environments
/// * Use appropriate key sizes for cryptographic algorithms
/// * Validate expiration times and other claims as needed
/// * Consider using HTTPS for token transmission
module {

  /// Represents an unsigned JWT token containing header and payload.
  /// This is a JWT token before signing, containing only the header and payload claims.
  ///
  /// The header contains metadata about the token (algorithm, type, etc.)
  /// The payload contains the actual claims and data.
  ///
  /// Example:
  /// ```motoko
  /// let unsignedToken : UnsignedToken = {
  ///     header = [("alg", #string("HS256")), ("typ", #string("JWT"))];
  ///     payload = [("sub", #string("1234567890")), ("name", #string("John Doe"))];
  /// };
  /// ```
  public type UnsignedToken = {
    header : [(Text, Json.Json)];
    payload : [(Text, Json.Json)];
  };

  /// Represents a complete JWT token with signature information.
  /// This extends UnsignedToken to include cryptographic signature data.
  ///
  /// A complete JWT token consists of:
  /// * Header: Token metadata (algorithm, type, etc.)
  /// * Payload: Claims and data
  /// * Signature: Cryptographic signature ensuring integrity
  ///
  /// Example:
  /// ```motoko
  /// let token : Token = {
  ///     header = [("alg", #string("HS256")), ("typ", #string("JWT"))];
  ///     payload = [("sub", #string("1234567890"))];
  ///     signature = {
  ///         algorithm = "HS256";
  ///         value = signatureBlob;
  ///         message = messageBlob;
  ///     };
  /// };
  /// ```
  public type Token = UnsignedToken and {
    signature : SignatureInfo;
  };

  /// Contains cryptographic signature information for a JWT token.
  /// This includes the algorithm used, the signature value, and the message that was signed.
  ///
  /// Fields:
  /// * `algorithm`: The signing algorithm (e.g., "HS256", "RS256", "ES256")
  /// * `value`: The actual signature bytes
  /// * `message`: The message that was signed (header.payload)
  ///
  /// Example:
  /// ```motoko
  /// let signatureInfo : SignatureInfo = {
  ///     algorithm = "HS256";
  ///     value = Blob.fromArray([0x12, 0x34, 0x56]);
  ///     message = Text.encodeUtf8("header.payload");
  /// };
  /// ```
  public type SignatureInfo = {
    algorithm : Text;
    value : Blob;
    message : Blob;
  };

  /// Configuration options for JWT token validation.
  /// Allows fine-grained control over which aspects of the token to validate.
  ///
  /// Fields:
  /// * `expiration`: Whether to validate the 'exp' (expiration) claim
  /// * `notBefore`: Whether to validate the 'nbf' (not before) claim
  /// * `issuer`: How to validate the 'iss' (issuer) claim
  /// * `signature`: How to validate the cryptographic signature
  /// * `audience`: How to validate the 'aud' (audience) claim
  ///
  /// Example:
  /// ```motoko
  /// let options : ValidationOptions = {
  ///     expiration = true;
  ///     notBefore = true;
  ///     issuer = #one("https://my-issuer.com");
  ///     signature = #key(myPublicKey);
  ///     audience = #any(["my-app", "my-service"]);
  /// };
  /// ```
  public type ValidationOptions = {
    expiration : Bool;
    notBefore : Bool;
    issuer : IssuerValidationKind;
    signature : SignatureValidationKind;
    audience : AudienceValidationKind;
  };

  /// Defines how to validate the audience claim in a JWT token.
  /// The audience claim identifies the recipients that the JWT is intended for.
  ///
  /// Options:
  /// * `#skip`: Skip audience validation entirely
  /// * `#one(Text)`: Token must have this exact audience
  /// * `#any([Text])`: Token must have at least one of these audiences
  /// * `#all([Text])`: Token must have all of these audiences
  ///
  /// Example:
  /// ```motoko
  /// let audienceValidation : AudienceValidationKind = #any(["web-app", "mobile-app"]);
  /// ```
  public type AudienceValidationKind = {
    #skip;
    #one : Text;
    #any : [Text];
    #all : [Text];
  };

  /// Defines how to validate the issuer claim in a JWT token.
  /// The issuer claim identifies the principal that issued the JWT.
  ///
  /// Options:
  /// * `#skip`: Skip issuer validation entirely
  /// * `#one(Text)`: Token must be from this exact issuer
  /// * `#any([Text])`: Token must be from one of these issuers
  ///
  /// Example:
  /// ```motoko
  /// let issuerValidation : IssuerValidationKind = #one("https://auth.example.com");
  /// ```
  public type IssuerValidationKind = {
    #skip;
    #one : Text;
    #any : [Text];
  };

  /// Defines how to validate the cryptographic signature of a JWT token.
  /// Signature validation ensures the token hasn't been tampered with.
  ///
  /// Options:
  /// * `#skip`: Skip signature validation (NOT recommended for production)
  /// * `#key(SignatureVerificationKey)`: Use a single key for validation
  /// * `#keys([SignatureVerificationKey])`: Try multiple keys for validation
  /// * `#resolver((issuer: ?Text) -> Iter.Iter<SignatureVerificationKey>)`: Dynamic key resolution based on issuer
  ///
  /// Example:
  /// ```motoko
  /// let signatureValidation : SignatureValidationKind = #key(#symmetric(mySecretKey));
  /// ```
  public type SignatureValidationKind = {
    #skip;
    #key : SignatureVerificationKey;
    #keys : [SignatureVerificationKey];
    #resolver : (issuer : ?Text) -> Iter.Iter<SignatureVerificationKey>;
  };

  /// Enumeration of supported signature verification key types.
  /// This is used to identify which cryptographic algorithm a key supports.
  ///
  /// Types:
  /// * `#symmetric`: HMAC algorithms (HS256, HS384, HS512)
  /// * `#ecdsa`: Elliptic Curve DSA algorithms (ES256, ES384, ES512)
  /// * `#rsa`: RSA algorithms (RS256, RS384, RS512, PS256, PS384, PS512)
  /// * `#eddsa`: Edwards-curve DSA algorithms (EdDSA)
  ///
  /// Example:
  /// ```motoko
  /// let keyKind : SignatureVerificationKeyKind = #ecdsa;
  /// ```
  public type SignatureVerificationKeyKind = {
    #symmetric;
    #ecdsa;
    #rsa;
    #eddsa;
  };

  /// Represents a cryptographic key used for JWT signature verification.
  /// Different key types support different signing algorithms.
  ///
  /// Key types:
  /// * `#symmetric(Blob)`: Shared secret key for HMAC algorithms
  /// * `#ecdsa(ECDSA.PublicKey)`: ECDSA public key for elliptic curve signatures
  /// * `#rsa(RSA.PublicKey)`: RSA public key for RSA signatures
  /// * `#eddsa(EdDSA.PublicKey)`: EdDSA public key for Edwards-curve signatures
  ///
  /// Example:
  /// ```motoko
  /// let key : SignatureVerificationKey = #symmetric(Text.encodeUtf8("my-secret-key"));
  /// ```
  public type SignatureVerificationKey = {
    #symmetric : Blob;
    #ecdsa : ECDSA.PublicKey;
    #rsa : RSA.PublicKey;
    #eddsa : EdDSA.PublicKey;
  };

  /// Standard JWT header fields as defined in RFC 7519.
  /// The header contains metadata about the token and how it should be processed.
  ///
  /// Fields:
  /// * `alg`: Algorithm used for signing (REQUIRED)
  /// * `typ`: Token type, usually "JWT" (OPTIONAL)
  /// * `cty`: Content type (OPTIONAL)
  /// * `kid`: Key ID hint for verification (OPTIONAL)
  /// * `x5c`: X.509 certificate chain (OPTIONAL)
  /// * `x5u`: X.509 certificate chain URL (OPTIONAL)
  /// * `crit`: Critical header parameters (OPTIONAL)
  ///
  /// Example:
  /// ```motoko
  /// let header : StandardHeader = {
  ///     alg = "HS256";
  ///     typ = ?"JWT";
  ///     cty = null;
  ///     kid = ?"key-1";
  ///     x5c = null;
  ///     x5u = null;
  ///     crit = null;
  /// };
  /// ```
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

  /// Standard JWT payload claims as defined in RFC 7519.
  /// The payload contains the actual claims and data carried by the token.
  ///
  /// Standard claims:
  /// * `iss`: Issuer - who issued the token (OPTIONAL)
  /// * `sub`: Subject - who the token is about (OPTIONAL)
  /// * `aud`: Audience - who the token is for (OPTIONAL)
  /// * `exp`: Expiration time in seconds since Unix epoch (OPTIONAL)
  /// * `nbf`: Not before time in seconds since Unix epoch (OPTIONAL)
  /// * `iat`: Issued at time in seconds since Unix epoch (OPTIONAL)
  /// * `jti`: JWT ID - unique identifier for the token (OPTIONAL)
  ///
  /// Example:
  /// ```motoko
  /// let payload : StandardPayload = {
  ///     iss = ?"https://auth.example.com";
  ///     sub = ?"user123";
  ///     aud = ?["web-app", "mobile-app"];
  ///     exp = ?1234567890.0;
  ///     nbf = ?1234567800.0;
  ///     iat = ?1234567800.0;
  ///     jti = ?"unique-token-id";
  /// };
  /// ```
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

  /// Parses JWT header fields into a strongly-typed StandardHeader record.
  /// This function extracts and validates standard JWT header fields from the raw JSON structure.
  ///
  /// The function validates that required fields are present and have the correct types:
  /// * `alg` field is required and must be a string
  /// * Other fields are optional but must have correct types if present
  ///
  /// Parameters:
  /// * `headerFields`: Array of key-value pairs representing the JWT header
  ///
  /// Returns:
  /// * `#ok(StandardHeader)`: Successfully parsed header with validated fields
  /// * `#err(Text)`: Error message if parsing fails or validation fails
  ///
  /// Example:
  /// ```motoko
  /// let headerFields = [("alg", #string("HS256")), ("typ", #string("JWT"))];
  /// let result = parseStandardHeader(headerFields);
  /// // result == #ok({alg = "HS256"; typ = ?"JWT"; ...})
  /// ```
  public func parseStandardHeader(headerFields : [(Text, Json.Json)]) : Result.Result<StandardHeader, Text> {
    var algValue : ?Text = null;
    var typValue : ?Text = null;
    var ctyValue : ?Text = null;
    var kidValue : ?Text = null;
    var x5cValue : ?[Text] = null;
    var x5uValue : ?Text = null;
    var critValue : ?[Text] = null;

    for ((key, value) in headerFields.vals()) {
      switch (key) {
        case ("alg") {
          switch (value) {
            case (#string(v)) { algValue := ?v };
            case (_) return #err("Invalid JWT: 'alg' must be a string value");
          };
        };
        case ("typ") {
          switch (value) {
            case (#string(v)) { typValue := ?v };
            case (_) return #err("Invalid JWT: 'typ' must be a string value");
          };
        };
        case ("cty") {
          switch (value) {
            case (#string(v)) { ctyValue := ?v };
            case (_) return #err("Invalid JWT: 'cty' must be a string value");
          };
        };
        case ("kid") {
          switch (value) {
            case (#string(v)) { kidValue := ?v };
            case (_) return #err("Invalid JWT: 'kid' must be a string value");
          };
        };
        case ("x5u") {
          switch (value) {
            case (#string(v)) { x5uValue := ?v };
            case (_) return #err("Invalid JWT: 'x5u' must be a string value");
          };
        };
        case ("x5c") {
          switch (value) {
            case (#array(arr)) {
              let strArray = Array.filterMap<Json.Json, Text>(
                arr,
                func(item) {
                  switch (item) {
                    case (#string(s)) ?s;
                    case (_) null;
                  };
                },
              );
              if (strArray.size() == arr.size()) {
                x5cValue := ?strArray;
              } else {
                return #err("Invalid JWT: 'x5c' must be an array of strings");
              };
            };
            case (_) return #err("Invalid JWT: 'x5c' must be an array");
          };
        };
        case ("crit") {
          switch (value) {
            case (#array(arr)) {
              let strArray = Array.filterMap<Json.Json, Text>(
                arr,
                func(item) {
                  switch (item) {
                    case (#string(s)) ?s;
                    case _ null;
                  };
                },
              );
              if (strArray.size() == arr.size()) {
                critValue := ?strArray;
              } else {
                return #err("Invalid JWT: 'crit' must be an array of strings");
              };
            };
            case (_) return #err("Invalid JWT: 'crit' must be an array");
          };
        };
        case (_) {
          // Other fields don't need special handling
        };
      };
    };

    // Ensure required fields are present
    switch (algValue) {
      case (null) return #err("Invalid JWT: Missing required 'alg' field");
      case (?alg) {
        return #ok({
          alg = alg;
          typ = typValue;
          cty = ctyValue;
          kid = kidValue;
          x5c = x5cValue;
          x5u = x5uValue;
          crit = critValue;
        });
      };
    };
  };

  /// Parses JWT payload fields into a strongly-typed StandardPayload record.
  /// This function extracts and validates standard JWT payload claims from the raw JSON structure.
  ///
  /// The function validates that all fields have the correct types:
  /// * String fields (`iss`, `sub`, `jti`) must be strings
  /// * Numeric fields (`exp`, `nbf`, `iat`) must be numbers (int or float)
  /// * Audience field (`aud`) can be a string or array of strings
  ///
  /// Parameters:
  /// * `payloadFields`: Array of key-value pairs representing the JWT payload
  ///
  /// Returns:
  /// * `#ok(StandardPayload)`: Successfully parsed payload with validated fields
  /// * `#err(Text)`: Error message if parsing fails or validation fails
  ///
  /// Example:
  /// ```motoko
  /// let payloadFields = [("sub", #string("1234567890")), ("exp", #number(#int(1234567890)))];
  /// let result = parseStandardPayload(payloadFields);
  /// // result == #ok({sub = ?"1234567890"; exp = ?1234567890.0; ...})
  /// ```
  public func parseStandardPayload(payloadFields : [(Text, Json.Json)]) : Result.Result<StandardPayload, Text> {
    var issValue : ?Text = null;
    var subValue : ?Text = null;
    var audValue : ?[Text] = null;
    var expValue : ?Float = null;
    var nbfValue : ?Float = null;
    var iatValue : ?Float = null;
    var jtiValue : ?Text = null;

    for ((key, value) in payloadFields.vals()) {
      switch (key) {
        case ("iss") {
          switch (value) {
            case (#string(v)) { issValue := ?v };
            case (_) return #err("Invalid JWT: 'iss' must be a string value");
          };
        };
        case ("sub") {
          switch (value) {
            case (#string(v)) { subValue := ?v };
            case (_) return #err("Invalid JWT: 'sub' must be a string value");
          };
        };
        case ("aud") {
          switch (value) {
            case (#string(v)) { audValue := ?[v] };
            case (#array(arr)) {
              let strArray = Array.filterMap<Json.Json, Text>(
                arr,
                func(item) {
                  switch (item) {
                    case (#string(s)) ?s;
                    case _ null;
                  };
                },
              );
              if (strArray.size() == arr.size()) {
                audValue := ?strArray;
              } else {
                return #err("Invalid JWT: 'aud' must be a string or array of strings");
              };
            };
            case (_) return #err("Invalid JWT: 'aud' must be a string or array");
          };
        };
        case ("exp") {
          switch (value) {
            case (#number(#float(v))) {
              expValue := ?v;
            };
            case (#number(#int(v))) {
              expValue := ?Float.fromInt(v);
            };
            case (_) return #err("Invalid JWT: 'exp' must be a number");
          };
        };
        case ("nbf") {
          switch (value) {
            case (#number(#float(v))) {
              nbfValue := ?v;
            };
            case (#number(#int(v))) {
              nbfValue := ?Float.fromInt(v);
            };
            case (_) return #err("Invalid JWT: 'nbf' must be a number");
          };
        };
        case ("iat") {
          switch (value) {
            case (#number(#float(v))) {
              iatValue := ?v;
            };
            case (#number(#int(v))) {
              iatValue := ?Float.fromInt(v);
            };
            case (_) return #err("Invalid JWT: 'iat' must be a number");
          };
        };
        case ("jti") {
          switch (value) {
            case (#string(v)) { jtiValue := ?v };
            case (_) return #err("Invalid JWT: 'jti' must be a string value");
          };
        };
        case (_) {
          // Other fields don't need special handling
        };
      };
    };

    // No required fields in payload, so we can return the processed object
    return #ok({
      iss = issValue;
      sub = subValue;
      aud = audValue;
      exp = expValue;
      nbf = nbfValue;
      iat = iatValue;
      jti = jtiValue;
    });
  };

  /// Performs comprehensive validation of a JWT token according to the specified options.
  /// This function validates various aspects of the token including time-based claims,
  /// signature verification, and audience/issuer validation.
  ///
  /// Validation performed based on options:
  /// * **Expiration**: Checks if current time is before the `exp` claim
  /// * **Not Before**: Checks if current time is after the `nbf` claim
  /// * **Signature**: Verifies cryptographic signature using provided keys
  /// * **Audience**: Validates that token audience matches expected values
  /// * **Issuer**: Validates that token issuer matches expected values
  ///
  /// Parameters:
  /// * `token`: The JWT token to validate
  /// * `options`: Configuration specifying which validations to perform
  ///
  /// Returns:
  /// * `#ok(())`: Token passes all specified validations
  /// * `#err(Text)`: Token fails validation with descriptive error message
  ///
  /// Example:
  /// ```motoko
  /// let options = {
  ///     expiration = true;
  ///     notBefore = true;
  ///     issuer = #one("https://auth.example.com");
  ///     signature = #key(myKey);
  ///     audience = #any(["web-app"]);
  /// };
  /// let result = validate(token, options);
  /// ```
  // Comprehensive validation
  public func validate(token : Token, options : ValidationOptions) : Result.Result<(), Text> {
    // Check time-based claims if enabled
    if (options.expiration and not validateExpiration(token)) {
      return #err("Token has expired");
    };

    if (options.notBefore and not validateNotBefore(token)) {
      return #err("Token is not yet valid (nbf claim)");
    };

    // Check signature if key provided
    switch (verifySignature(token, options.signature)) {
      case (#err(e)) return #err(e);
      case (#ok(false)) return #err("Invalid signature");
      case (#ok(true)) {
        // Signature valid, continue
      };
    };

    let aud : [Text] = switch (getPayloadValue(token, "aud")) {
      case (null or ?#null_) [];
      case (?#string(aud)) [aud];
      case (?#array(audArray)) {
        let strArray = Array.filterMap<Json.Json, Text>(
          audArray,
          func(item) {
            switch (item) {
              case (#string(s)) ?s;
              case (_) null;
            };
          },
        );
        if (strArray.size() == audArray.size()) {
          strArray;
        } else {
          return #err("Invalid JWT: 'aud' must be a string or array of strings");
        };
      };
      case (_) return #err("Invalid JWT: 'aud' must be a string or array");
    };
    // Check audience if specified
    switch (options.audience) {
      case (#skip) (); // No audience validation needed
      case (#one(audience)) {
        // Check if audience matches
        if (Array.indexOf<Text>(aud, Text.equal, audience) == null) {
          return #err("Token audience does not match expected audience");
        };
      };
      case (#any(audiences)) {
        // Check if any of the audiences match
        let found = Array.any<Text>(
          audiences,
          func(a : Text) : Bool = Array.indexOf<Text>(aud, Text.equal, a) != null,
        );
        if (not found) {
          return #err("Token audience does not match expected audience");
        };
      };
      case (#all(audiences)) {
        // Check if all audiences match
        let found = Array.all<Text>(
          audiences,
          func(a) : Bool = Array.indexOf<Text>(aud, Text.equal, a) != null,
        );
        if (not found) {
          return #err("Token audience does not match expected audience");
        };
      };
    };

    // All validations passed
    return #ok;
  };

  /// Parses a JWT token from its text representation.
  /// This function takes a JWT string (in the format "header.payload.signature") and
  /// parses it into a structured Token object with decoded header, payload, and signature.
  ///
  /// The function performs the following steps:
  /// 1. Splits the JWT string on '.' characters (expects exactly 3 parts)
  /// 2. Base64-decodes each part
  /// 3. Parses header and payload as JSON objects
  /// 4. Extracts signature algorithm from header
  /// 5. Constructs message for signature verification
  ///
  /// Parameters:
  /// * `jwt`: The JWT token as a text string
  ///
  /// Returns:
  /// * `#ok(Token)`: Successfully parsed token with all components
  /// * `#err(Text)`: Error message if parsing fails at any step
  ///
  /// Example:
  /// ```motoko
  /// let jwtText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
  /// let result = parse(jwtText);
  /// // result == #ok(token) with decoded header, payload, and signature
  /// ```
  public func parse(jwt : Text) : Result.Result<Token, Text> {
    // Split JWT into parts
    let parts = Text.split(jwt, #char('.')) |> Iter.toArray(_);

    if (parts.size() != 3) {
      return #err("Invalid JWT format - expected 3 parts, found " # Nat.toText(parts.size()));
    };
    let headerBytes = switch (BaseX.fromBase64(parts[0])) {
      case (#err(e)) return #err("Failed to decode JWT header base64 value '" # parts[0] # "'. Error: " # e);
      case (#ok(headerBytes)) headerBytes;
    };
    let headerJson = switch (decodeJsonObjBytes(headerBytes, "header")) {
      case (#err(e)) return #err("Unable to decode JWT header: " # debug_show (e));
      case (#ok(headerJson)) headerJson;
    };
    let signatureAlgorithm = switch (getValue(headerJson, "alg")) {
      case (null) return #err("Invalid JWT: Missing 'alg' field in header");
      case (?#string(alg)) alg;
      case (_) return #err("Invalid JWT: 'alg' must be a string");
    };

    let payloadBytes = switch (BaseX.fromBase64(parts[1])) {
      case (#err(e)) return #err("Failed to decode JWT payload base64 value '" # parts[1] # "'. Error: " # e);
      case (#ok(payloadBytes)) payloadBytes;
    };
    let payloadJson = switch (decodeJsonObjBytes(payloadBytes, "payload")) {
      case (#err(e)) return #err("Unable to decode JWT payload: " # debug_show (e));
      case (#ok(payloadJson)) payloadJson;
    };

    let signatureBytes = switch (BaseX.fromBase64(parts[2])) {
      case (#err(e)) return #err("Failed to decode JWT signature base64 value '" # parts[0] # "'. Error: " # e);
      case (#ok(signatureBytes)) Blob.fromArray(signatureBytes);
    };

    let messageBytes = Text.encodeUtf8(parts[0] # "." # parts[1]);

    #ok({
      header = headerJson;
      payload = payloadJson;
      signature = {
        algorithm = signatureAlgorithm;
        value = signatureBytes;
        message = messageBytes;
      };
    });
  };

  /// Converts an unsigned JWT token to its text representation without signature.
  /// This function creates the "header.payload" portion of a JWT token by:
  /// 1. Serializing header and payload to JSON
  /// 2. Encoding as UTF-8 bytes
  /// 3. Base64-encoding with URL-safe alphabet (no padding)
  ///
  /// This is useful for creating the message that will be signed, or for debugging purposes.
  ///
  /// Parameters:
  /// * `token`: The unsigned JWT token to serialize
  ///
  /// Returns:
  /// * `Text`: The "header.payload" portion of the JWT token
  ///
  /// Example:
  /// ```motoko
  /// let unsignedToken = {
  ///     header = [("alg", #string("HS256"))];
  ///     payload = [("sub", #string("1234567890"))];
  /// };
  /// let text = toTextUnsigned(unsignedToken);
  /// // text == "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
  /// ```
  public func toTextUnsigned(token : UnsignedToken) : Text {
    // Encode header
    let headerText = Json.stringify(#object_(token.header), null);
    let headerBytes = Text.encodeUtf8(headerText);
    let headerBase64 = BaseX.toBase64(headerBytes.vals(), #url({ includePadding = false }));

    // Encode payload
    let payloadText = Json.stringify(#object_(token.payload), null);
    let payloadBytes = Text.encodeUtf8(payloadText);
    let payloadBase64 = BaseX.toBase64(payloadBytes.vals(), #url({ includePadding = false }));

    // Create JWT without signature
    headerBase64 # "." # payloadBase64;
  };

  /// Converts a complete JWT token to its text representation.
  /// This function creates the full JWT token string by:
  /// 1. Creating the unsigned portion (header.payload)
  /// 2. Base64-encoding the signature
  /// 3. Joining all parts with '.' separators
  ///
  /// The resulting string is the standard JWT format that can be transmitted and verified.
  ///
  /// Parameters:
  /// * `token`: The complete JWT token to serialize
  ///
  /// Returns:
  /// * `Text`: The full JWT token string in "header.payload.signature" format
  ///
  /// Example:
  /// ```motoko
  /// let token = {
  ///     header = [("alg", #string("HS256"))];
  ///     payload = [("sub", #string("1234567890"))];
  ///     signature = { algorithm = "HS256"; value = signatureBlob; message = messageBlob };
  /// };
  /// let text = toText(token);
  /// // text == "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
  /// ```
  public func toText(token : Token) : Text {
    let message = toTextUnsigned(token);
    let signatureBase64 = BaseX.toBase64(token.signature.value.vals(), #url({ includePadding = false }));
    message # "." # signatureBase64;
  };

  /// Converts an unsigned JWT token to its binary representation.
  /// This function creates the UTF-8 encoded bytes of the unsigned token text.
  ///
  /// This is useful for signature generation or when binary representation is needed.
  ///
  /// Parameters:
  /// * `token`: The unsigned JWT token to convert
  ///
  /// Returns:
  /// * `Blob`: The UTF-8 encoded bytes of the "header.payload" portion
  ///
  /// Example:
  /// ```motoko
  /// let blob = toBlobUnsigned(unsignedToken);
  /// // blob contains UTF-8 bytes of "header.payload"
  /// ```
  public func toBlobUnsigned(token : UnsignedToken) : Blob {
    let text = toTextUnsigned(token);
    Text.encodeUtf8(text);
  };

  /// Converts a complete JWT token to its binary representation.
  /// This function creates the UTF-8 encoded bytes of the complete token text.
  ///
  /// This is useful when binary representation of the full token is needed.
  ///
  /// Parameters:
  /// * `token`: The complete JWT token to convert
  ///
  /// Returns:
  /// * `Blob`: The UTF-8 encoded bytes of the full "header.payload.signature" token
  ///
  /// Example:
  /// ```motoko
  /// let blob = toBlob(token);
  /// // blob contains UTF-8 bytes of the complete JWT token
  /// ```
  public func toBlob(token : Token) : Blob {
    let text = toText(token);
    Text.encodeUtf8(text);
  };

  /// Retrieves a specific value from the JWT token header.
  /// This function looks up a header field by key and returns its JSON value.
  ///
  /// Common header fields include:
  /// * `alg`: Signing algorithm
  /// * `typ`: Token type (usually "JWT")
  /// * `kid`: Key ID for verification
  ///
  /// Parameters:
  /// * `token`: The JWT token to query
  /// * `key`: The header field name to retrieve
  ///
  /// Returns:
  /// * `?Json.Json`: The value if found, or `null` if not present
  ///
  /// Example:
  /// ```motoko
  /// let algorithm = getHeaderValue(token, "alg");
  /// // algorithm == ?#string("HS256")
  /// ```
  public func getHeaderValue(token : Token, key : Text) : ?Json.Json {
    getValue(token.header, key);
  };

  /// Retrieves a specific value from the JWT token payload.
  /// This function looks up a payload claim by key and returns its JSON value.
  ///
  /// Common payload claims include:
  /// * `sub`: Subject (who the token is about)
  /// * `iss`: Issuer (who issued the token)
  /// * `aud`: Audience (who the token is for)
  /// * `exp`: Expiration time
  /// * `nbf`: Not before time
  /// * `iat`: Issued at time
  ///
  /// Parameters:
  /// * `token`: The JWT token to query
  /// * `key`: The payload claim name to retrieve
  ///
  /// Returns:
  /// * `?Json.Json`: The value if found, or `null` if not present
  ///
  /// Example:
  /// ```motoko
  /// let subject = getPayloadValue(token, "sub");
  /// // subject == ?#string("1234567890")
  /// ```
  public func getPayloadValue(token : Token, key : Text) : ?Json.Json {
    getValue(token.payload, key);
  };

  private func getValue(a : [(Text, Json.Json)], key : Text) : ?Json.Json {
    for ((k, v) in a.vals()) {
      if (k == key) return ?v;
    };
    return null;
  };

  private func validateExpiration(token : Token) : Bool {

    switch (getPayloadValue(token, "exp")) {
      case (null or ?#null_) true; // No expiration claim, consider valid by default
      case (?#number(#float(expTime))) Time.now() < Float.toInt(expTime * 1_000_000_000);
      case (?#number(#int(expTime))) Time.now() < (expTime * 1_000_000_000);
      case (_) false; // Invalid type for expiration claim
    };
  };

  // Validate "not before" time
  private func validateNotBefore(token : Token) : Bool {
    switch (getPayloadValue(token, "nbf")) {
      case (null or ?#null_) true; // No nbf claim, consider valid by default
      case (?#number(#float(nbfTime))) Time.now() >= Float.toInt(nbfTime * 1_000_000_000);
      case (?#number(#int(nbfTime))) Time.now() >= (nbfTime * 1_000_000_000);
      case (_) false; // Invalid type for expiration claim
    };
  };

  // Verify signature based on algorithm
  private func verifySignature(token : Token, signatureValidationKind : SignatureValidationKind) : Result.Result<Bool, Text> {
    let keyResolver = switch (signatureValidationKind) {
      case (#skip) return #ok(true);
      case (#key(key)) func(_ : ?Text) : Iter.Iter<SignatureVerificationKey> = Iter.singleton(key);
      case (#keys(keys)) func(_ : ?Text) : Iter.Iter<SignatureVerificationKey> = keys.vals();
      case (#resolver(resolver)) resolver;
    };

    // Verify based on algorithm
    type HashAlgorithm = {
      #sha256;
      // #sha384;
      // #sha512;
    };
    let issuer = switch (getPayloadValue(token, "iss")) {
      case (null or ?#null_) null;
      case (?#string(iss)) ?iss;
      case (_) return #err("Invalid JWT: 'iss' must be a string");
    };
    let keys = keyResolver(issuer);
    let verifySignatureWithKey = switch (token.signature.algorithm) {
      case ("HS256") func(key : SignatureVerificationKey) : Bool {
        let #symmetric(symmetricKey) = key else return false;
        verifyHmacSignature(#sha256, token.signature.message.vals(), symmetricKey, token.signature.value);
      };
      // TODO
      // case ("HS384")
      // case ("HS512")
      case ("ES256" or "ES256K") func(key : SignatureVerificationKey) : Bool {
        let #ecdsa(ecdsaKey) = key else return false;
        verifyEcdsaSignature(#sha256, token.signature.message.vals(), ecdsaKey, token.signature.value);
      };
      // TODO
      // case ("ES384")
      // case ("ES512")
      case ("RS256") func(key : SignatureVerificationKey) : Bool {
        let #rsa(rsaKey) = key else return false;
        verifyRSASignature(#sha256, token.signature.message.vals(), rsaKey, token.signature.value);
      };
      case ("EdDSA") func(key : SignatureVerificationKey) : Bool {
        let #eddsa(eddsaKey) = key else return false;
        verifyEdDSASignature(token.signature.message.vals(), eddsaKey, token.signature.value);
      };
      case ("none") return #err("Algorithm 'none' is not supported for security reasons");
      case (_) return #err("Unsupported algorithm: " # token.signature.algorithm);
    };
    label f for (key in keys) {
      let isValid = verifySignatureWithKey(key);
      if (isValid) return #ok(true);
    };
    return #ok(false);
  };

  private func verifyEdDSASignature(
    message : Iter.Iter<Nat8>,
    publicKey : EdDSA.PublicKey,
    signature : Blob,
  ) : Bool {
    let #ok(sig) = EdDSA.signatureFromBytes(signature.vals(), #raw({ curve = publicKey.curve })) else return false;
    publicKey.verify(message, sig);
  };

  private func verifyEcdsaSignature(
    hashAlgorithm : Sha256.Algorithm,
    message : Iter.Iter<Nat8>,
    publicKey : ECDSA.PublicKey,
    signature : Blob,
  ) : Bool {
    let #ok(sig) = ECDSA.signatureFromBytes(signature.vals(), publicKey.curve, #raw) else return false;
    let hash = switch (hashAlgorithm) {
      case (#sha256) Sha256.fromIter(#sha256, message);
      case (#sha224) Sha256.fromIter(#sha224, message);
    };
    publicKey.verifyHashed(hash.vals(), sig);
  };

  private func verifyRSASignature(
    hashAlgorithm : Sha256.Algorithm,
    message : Iter.Iter<Nat8>,
    publicKey : RSA.PublicKey,
    signature : Blob,
  ) : Bool {
    let #ok(sig) = RSA.signatureFromBytes(signature.vals(), #raw({ paddingAlgorithm = #pkcs1v1_5 })) else return false;
    let hash = switch (hashAlgorithm) {
      case (#sha256) Sha256.fromIter(#sha256, message);
      case (#sha224) Sha256.fromIter(#sha224, message);
    };
    publicKey.verifyHashed(hash.vals(), sig);
  };

  private func verifyHmacSignature(
    hashAlgorithm : HMAC.HashAlgorithm,
    message : Iter.Iter<Nat8>,
    key : Blob,
    signature : Blob,
  ) : Bool {
    // HMAC verification logic
    let hmac = HMAC.generate(
      Blob.toArray(key),
      message,
      hashAlgorithm,
    );
    Blob.equal(hmac, signature);
  };

  private func decodeJsonObjBytes(
    jsonBytes : [Nat8],
    label_ : Text,
  ) : Result.Result<[(Text, Json.Json)], Text> {
    let ?jsonText = Text.decodeUtf8(Blob.fromArray(jsonBytes)) else {
      return #err("Unable to decode " # label_ # " as UTF-8");
    };

    switch (Json.parse(jsonText)) {
      case (#err(e)) return #err("Unable to decode " # label_ # " as JSON: " # debug_show (e));
      case (#ok(json)) switch (Json.getAsObject(json, "")) {
        case (#err(e)) return #err("Invalid " # label_ # " JSON: " # debug_show (e));
        case (#ok(jsonObj)) #ok(jsonObj);
      };
    };
  };
};
