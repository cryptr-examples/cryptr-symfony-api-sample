# Cryptr with Symfony API

## 02 - Validate access tokens

### Install dependencies

🛠️️ To begin, install these dependencies using composer:

```bash
composer require symfony/maker-bundle --dev
composer require doctrine/annotations
composer require symfony/debug-bundle --dev
composer require symfony/security-bundle
composer require firebase/php-jwt
composer require symfony/http-client
composer require nelmio/cors-bundle
```

### Create sample resource controller

🛠 First, create a `CourseController`. We'll use the [symfony/maker bundle](https://symfony.com/blog/introducing-the-symfony-maker-bundle) to generate it:

```bash
php bin/console make:controller CourseController
```

Note: __The purpose of the controller is to receive a request (which has already been selected by a route) and to define the appropriate response.__

🛠️️ Now open up `src/Controller/CourseController.php` and replace its content with the following:

```php
<?php
 
namespace App\Controller;
 
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
 
class CourseController extends AbstractController
{
   /**
    * @Route("/api/v1/courses", name="courses")
    */
   public function index(): JsonResponse
   {
       $courses = [array(
               "id" => 1,
               "user_id" =>
               "eba25511-afce-4c8e-8cab-f82822434648",
               "title" => "learn git",
               "tags" => ["colaborate", "git" ,"cli", "commit", "versionning"],
               "img" => "https://carlchenet.com/wp-content/uploads/2019/04/git-logo.png",
               "desc" => "Learn how to create, manage, fork, and collaborate on a project. Git stays a major part of all companies projects. Learning git is learning how to make your project better everyday",
               "date" => '5 Nov',
               "timestamp" => 1604577600000,
               "teacher" => array(
                   "name" => "Max",
                   "picture" => "https://images.unsplash.com/photo-1558531304-a4773b7e3a9c?ixlib=rb-1.2.1&ixid=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=crop&w=634&q=80"
               )
           )];
       return new JsonResponse($courses);
   }
}
```

🛠️️ Run the server with command `symfony server:start` and open **insomnia** or **postman** to make a `GET` on `http://localhost:8000/api/v1/courses` request which should end with `200`

[Next](https://github.com/cryptr-examples/cryptr-symfony-api-sample/tree/03-add-your-cryptr-credentials)