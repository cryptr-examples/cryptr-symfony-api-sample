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
