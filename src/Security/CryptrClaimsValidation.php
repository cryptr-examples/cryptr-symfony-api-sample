<?php
namespace App\Security;
 
use DateTime;
use Exception;
use Psr\Log\LoggerInterface;
 
 
class JwtClaimsValidation
{
 public function __construct(LoggerInterface $logger)
 {
   $this->logger = $logger;
   $this->cryptrBaseUrl = $_ENV['CRYPTR_BASE_URL'];
   $this->cryptrTenantDomain = $_ENV['CRYPTR_TENANT_DOMAIN'];
 
   # Audiences
   $this->allowedOrigins = \explode(',', $_ENV['CRYPTR_ALLOWED_ORIGINS']);
   $this->allowedClientIds = \explode(',', $_ENV['CRYPTR_CLIENT_IDS']);
 }
 
 public function issuer()
 {
   return "{$this->cryptrBaseUrl}/t/{$this->cryptrTenantDomain}";
 }
  public function jwksUri()
 {
   return "{$this->issuer()}/.well-known";
 }
 
 public function validateResourceOwner($decodedToken, $userId)
 {
   if ($decodedToken->sub != $userId) {
     throw new Exception('The resource owner identifier (cryptr user id) of the JWT claim (sub) is not compliant');
   }
   return true;
 }
 
 public function validateScopes($decodedToken, $authorizedScopes)
 {
   if (array_intersect($decodedToken->scp, $authorizedScopes) != $decodedToken->scp){
     throw new Exception('The scopes of the JWT claim (scp) resource are not compliants');
   };
   return true;
 }
 
 private function currentTime() {
   return new DateTime();
 }
 
 public function validateExpiration($decodedToken) {
   $expiration = DateTime::createFromFormat( 'U', $decodedToken->exp );
 
   if ($expiration < $this->currentTime()){
     throw new Exception('The expiration of the JWT claim (exp) should be greater than current time');
   }
 
   return true;
 }
 
 public function validateIssuedAt($decodedToken) {
   $issuedAt = DateTime::createFromFormat( 'U', $decodedToken->iat );
 
   if ($this->currentTime() < $issuedAt){
     throw new Exception('The issuedAt of the JWT claim (iat) should be lower than current time');
   };
 
   return true;
 }
 
 public function validateNotBefore($decodedToken) {
   if(isset($decodedToken->nbf)) {
     $notBefore = DateTime::createFromFormat( 'U', $decodedToken->nbf );
 
     if ($this->currentTime() < $notBefore){
       throw new Exception('The notBefore of the JWT claim (iat) should be lower than current time');
     };
 
     return true;
   } else {
     $this->logger->info("'nbf key not present and not checked for now but will be in future");
     return true;
   }
 }
 
 public function validateIssuer($decodedToken) {
   if ($decodedToken->iss != $this->issuer()){
     throw new Exception('The JWT (iss) claim issuer must conform to issuer from config');
   };
 
   return true;
 }
 
 public function validateAudience($decodedToken) {
   if (!in_array($decodedToken->aud, $this->allowedOrigins)){
     throw new Exception('The JWT (aud) claim audience must conform to audience from config');
   };
 
   return true;
 }
 
 public function isValid($decodedToken)
 {
   // exp (Expiration Time)
   return $this->validateExpiration($decodedToken) &&
     // iat (Issued At)
     $this->validateIssuedAt($decodedToken) &&
     // nbf (Not before)
     $this->validateNotBefore($decodedToken)&&
     // iss (Issuer)
     $this->validateIssuer($decodedToken) &&
     // aud (Audience)
     $this->validateAudience($decodedToken);
 }
}