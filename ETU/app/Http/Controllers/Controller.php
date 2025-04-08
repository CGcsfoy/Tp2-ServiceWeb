<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

//HTTP Codes (rajouter ceux qui manque)
define('OK', 200);
define('CREATED', 201);
define('NO_CONTENT', 204);
define('UNAUTHORIZED', 401);
define('NOT_FOUND', 404);
define('TOO_MANY_REQUEST', 429);
define('INVALID_DATA', 422);
define('SERVER_ERROR', 500);

//Pagination
define('SEARCH_PAGINATION', 20);

//Roles
define('USER', 1);
define('ADMIN', 2);

/** * @OA\Info(title="TP2 API", version="0.1") */ 
class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
}
