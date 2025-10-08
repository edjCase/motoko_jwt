import JsonTypes "mo:json@1/Types";
import Iter "mo:core@1/Iter";
import EcdsaPublicKey "mo:ecdsa@7/PublicKey";
import RsaPublicKey "mo:rsa@2/PublicKey";
import EddsaPublicKey "mo:eddsa@2/PublicKey";

module {
  public type UnsignedToken = {
    header : [(Text, JsonTypes.Json)];
    payload : [(Text, JsonTypes.Json)];
  };

  public type Token = UnsignedToken and {
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
    #rsa;
    #eddsa;
  };

  public type SignatureVerificationKey = {
    #symmetric : Blob;
    #ecdsa : EcdsaPublicKey.PublicKey;
    #rsa : RsaPublicKey.PublicKey;
    #eddsa : EddsaPublicKey.PublicKey;
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
};
