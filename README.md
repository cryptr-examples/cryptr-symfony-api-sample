# Cryptr with Symfony API

## 04 - Protect API Endpoints

### Create User security entity

We must create a User class or an entity in order to register or authenticate a user in our application.

🛠️️ Head back to the terminal and create `user` with command `php bin/console make:user`

**The command above will ask you several questions:**

🛠️️ The name of the security user class (e.g. User) - `User`

🛠️️ Do you want to store user data in the database (via Doctrine)? (yes/no) - `no`

🛠️️ Enter a property name that will be the unique "display" name for the user (e.g. email, username, uuid) - `email`

🛠️️ Will this app need to hash/check user passwords? Choose No if passwords are not needed or will be checked/hashed by some other system (e.g. a single sign-on server) - `no`

### CryptrClaimsValidation and CryptrGuard

🛠️️ Create new files in `src/Security` folder, enter this command in your terminal:

```bash
touch src/Security/CryptrClaimsValidation.php src/Security/CryptrGuardAuthenticator.php
```

🛠️️ Now open up the newly created `src/Security/JwtClaimsValidation.php` file and paste in the following:

```php
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
   if(isset($decodedToken->jwt)) {
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
```

**CryptrClaimsValidation** allows you to validate the token (the user access token) before retrieving the response to the request.

🛠️️ Next, open up `src/Security/CryptrGuardAuthenticator.php` and paste in the following:

```php
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
```

**How the CryptrGuardAuthenticator proceeds:**

1. Read the access token in the header  
2. Guard read public key from Cryptr to validate the access token. If it succeeds, the response will be `200`, if not, it will be `401`.

Tip: __If some routes are public, developers can update `CryptrGuardAuthenticator::supports` methods to handle this, returning false will skip the authorization check__

### Use CryptrGuardAuthenticator

We are going to use the Symfony security component called `guard` for the authentication process.

🛠 Add `CryptrGuardAuthenticator` as application firewall in `config/packages/security.yaml`:

```yaml
security:
   # https://symfony.com/doc/current/security.html#where-do-users-come-from-user-providers
   providers:
       # used to reload user from session & other features (e.g. switch_user)
       app_user_provider:
           id: App\Security\UserProvider
   firewalls:
       dev:
           pattern: ^/(_(profiler|wdt)|css|images|js)/
           security: false
       main:
           anonymous: true
           lazy: true
           provider: app_user_provider
           # Add CryptrGuardAuthenticator:
           logout: ~
           guard:
               authenticators:
                   - App\Security\CryptrGuardAuthenticator
           stateless: true
 
           # activate different ways to authenticate
           # https://symfony.com/doc/current/security.html#firewalls-authentication
 
           # https://symfony.com/doc/current/security/impersonating_user.html
           # switch_user: true
 
   # Easy way to control access for large sections of your site
   # Note: Only the *first* access control that matches will be used
   access_control:
       # - { path: ^/admin, roles: ROLE_ADMIN }
       # - { path: ^/profile, roles: ROLE_USER }
```

Note: __firewalls is used to define how users will be authenticated__

⚠️ Symfony may run on HTTPS protocol, the client app should then target the related https url, if not, the browser will forbid the request due to CORS prohibiting redirections from http to https.

### Test with a Cryptr Vue app

Let’s try this on an application. For this purpose, we have an example app on Vue.

🛠 Run your code with `symfony server:start`

🛠Clone our `cryptr-vue-sample`:

```bash
git clone --branch 07-backend-courses-api https://github.com/cryptr-examples/cryptr-vue2-sample.git
```

🛠 Install the Vue project dependencies with `yarn`

🛠️️  Add `.env.local` file with your variables:

```javascript
VUE_APP_AUDIENCE=http://localhost:8080
VUE_APP_CLIENT_ID=YOUR_CLIENT_ID
VUE_APP_CRYPTR_BASE_URL=YOUR_BASE_URL
VUE_APP_DEFAULT_LOCALE=fr
VUE_APP_DEFAULT_REDIRECT_URI=http://localhost:8080
VUE_APP_TENANT_DOMAIN=YOUR_DOMAIN
VUE_APP_CRYPTR_TELEMETRY=FALSE
```

🛠️️ Open up the Profile Component in `src/views/Profile.vue` and modify the url request:

```vue
<script>
import { getCryptrClient } from "../CryptrPlugin";
export default {
 data() {
   return {
     courses: [],
     errors: [],
   };
 },
 created() {
   const client = getCryptrClient();
   console.log("created");
   client
     .decoratedRequest({
       method: "GET",
       // url: "http://localhost/api/v1/courses",
       // Replace localhost by 127.0.0.1 for Symfony:
       url: "http://127.0.0.1:8000/api/v1/courses",
     })
     .then((data) => {
       console.log(data);
       this.courses = data.data;
     })
     .catch((error) => {
       console.error(error);
       this.errors = [error];
     });
 },
};
</script>
```

🛠️️ Run vue server with `yarn serve` and try to connect. Your Vue application redirects you to your sign form page, where you can sign in or sign up with an email.

Note: __You can log in with a sandbox email and we send you a magic link which should directly arrive in your personal inbox.__

Once you're connected, click on "Protected route". You can now view the list of the courses.

It’s done, congratulations if you made it to the end!

I hope this was helpful, and thanks for following this tutorial! 🙂
