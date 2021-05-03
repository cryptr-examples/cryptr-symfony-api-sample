<?php
namespace App\Security;
 
use App\Security\User;
use App\Security\JwtClaimsValidation;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use \Firebase\JWT\JWK;
use \Firebase\JWT\JWT;
use Symfony\Component\String\UnicodeString;
use Symfony\Component\Config\Definition\Exception\Exception;
 
class CryptrGuardAuthenticator extends AbstractGuardAuthenticator
{
 private $logger;
 private $client;
 private $jwtClaims;
 
 public function __construct(HttpClientInterface $client, LoggerInterface $logger){
   $this->logger = $logger;
   $this->client = $client;
   $this->cryptrBaseUrl = $_ENV['CRYPTR_BASE_URL'];
   $this->cryptrTenantDomain = $_ENV['CRYPTR_TENANT_DOMAIN'];
   $this->jwtClaims = new JwtClaimsValidation($logger);
 }
 
 public function supports(Request $request): bool
 {
   return $request->getMethod() !== "OPTIONS";
 }
 
 public function getCredentials(Request $request)
 {
   $authHeader = $request->headers->get('Authorization', '');
   $authParts = \explode(" ", $authHeader);
   $prefix = new UnicodeString($authParts[0]);
   if($prefix->lower() == 'bearer') {
     return $authParts[1];
   } else {
     $exception = new Exception("Bearer token required");
     throw new AuthenticationException($exception->getMessage(), $exception->getCode(), $exception);
   }
 }
 
 private function issuer() {
   return "{$this->cryptrBaseUrl}/t/{$this->cryptrTenantDomain}";
 }
 private function jwksUri() {
   return "{$this->issuer()}/.well-known";
 }
 
 private function getJwks() {
   $response = $this->client->request(
     'GET',
     $this->jwksUri()
   );
   $keys = $response->toArray()['keys'];
   return ['keys' => $keys];
 }
 
 public function decodeJwt($jwt)
 {
   try {
     $publicKeys = JWK::parseKeySet($this->getJwks());
     $decodedJwt = JWT::decode($jwt, $publicKeys, array('RS256'));
     $this->jwtClaims->isValid($decodedJwt);
   } catch (\Throwable $exception) {
     throw new AuthenticationException($exception->getMessage(), $exception->getCode(), $exception);
   }
   return false;
 }
 
 public function getUser($credentials, UserProviderInterface $userProvider)
 {
   if($credentials == null || empty($credentials)) {
     return new User('unknown', null, ['IS_AUTHENTICATED_ANONYMOUSLY']);
   }
   return new User('unknown', null, ['IS_AUTHENTICATED_ANONYMOUSLY']);
 }
 
 public function checkCredentials($credentials, UserInterface $user): bool
 {
   try {
     if($credentials) {
       $this->decodeJwt($credentials);
     }
     return true;
   } catch( Exception $exception) {
     throw new AuthenticationException($exception->getMessage(), $exception->getCode(), $exception);
   }
 }
 
 public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
 {
   return null;
 }
 
 public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
 {
   $respBody = [
     'message' => sprintf(
       'Authentication failed: %s.',
       rtrim($exception->getMessage(), '.')
     )
     ];
   return new JsonResponse($respBody, JsonResponse::HTTP_UNAUTHORIZED);
 }
 
 public function start(Request $request, AuthenticationException $authException = null): Response
 {
   $data = [
     'message' => 'Authentication Required'
   ];
 
   return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
 }
 
 public function supportsRememberMe()
 {
   return false;
 }
}
