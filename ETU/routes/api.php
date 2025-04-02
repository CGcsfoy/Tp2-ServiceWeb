<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');



//Routes du TP2 ici : 
Route::get('/films', 'App\Http\Controllers\FilmController@index');
