<?php

namespace App\Http\Controllers;

use Auth;
use Illuminate\Database\QueryException;
use Validator;
use Hash;
use Illuminate\Http\Request;
use App\Models\User;
use App\Http\Resources\UserResource;
use App\Http\Requests\LoginUserRequest;
use App\Http\Requests\RegisterUserRequest;
use Illuminate\Support\Facades\Log;


class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     path="/api/signin",
     *     tags={"Authentification"},
     *     summary="Connexion",
     *     description="Permet à un utilisateur de se connecter",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"login", "password"},
     *             @OA\Property(property="login", type="string", example="johndoe"),
     *             @OA\Property(property="password", type="string", format="password", example="secret123")
     *         )
     *     ),
     *     @OA\Response(response=200, description="Connexion réussie"),
     *     @OA\Response(response=401, description="Identifiants invalides"),
     *     @OA\Response(response=404, description="Not Found"),
     *     @OA\Response(response=500, description="Erreur serveur")
     * )
     */
    public function login(LoginUserRequest $request)
    {
        try {
            if (Auth::attempt($request->only('login', 'password'))) {
                $user = Auth::user();
                $token = $user->createToken('auth_token')->plainTextToken;

                return response()->json([
                    'message' => 'Connexion réussie',
                    'access_token' => $token,
                    'user' => new UserResource($user),
                ], OK);
            }
            return response()->json(['message' => 'Identifiants invalides'], NOT_FOUND);
        } catch (\Exception $e) {
            Log::error('Erreur lors de la connexion : ' . $e->getMessage());
            return response()->json(['message' => 'Erreur serveur'], SERVER_ERROR);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/register",
     *     tags={"Authentification"},
     *     summary="Inscription",
     *     description="Enregistre un nouvel utilisateur",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"login", "first_name", "last_name", "email", "password"},
     *             @OA\Property(property="login", type="string", example="johndoe"),
     *             @OA\Property(property="first_name", type="string", example="John"),
     *             @OA\Property(property="last_name", type="string", example="Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="email_confirmation", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="secret123"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="secret123")
     *         )
     *     ),
     *     @OA\Response(response=201, description="Utilisateur enregistré avec succès"),
     *     @OA\Response(response=500, description="Erreur serveur")
     * )
     */
    public function register(RegisterUserRequest $request)
    {
        try {
            if (User::where('email', $request->email)->exists()) {
                return response()->json(['message' => 'Cet email est déjà utilisé.'], INVALID_DATA);
            }

            $user = User::create([
                'login' => $request->login,
                'first_name' => $request->first_name,
                'last_name' => $request->last_name,
                'email' => $request->email,
                'password' => bcrypt($request->password),
            ]);

            if (!$user) {
                return response()->json(['message' => 'Création impossible.'], NOT_FOUND);
            }

            return response()->json([
                'message' => 'Utilisateur enregistré avec succès',
                'user' => new UserResource($user),
            ], CREATED);

        } catch (\Exception $e) {
            Log::error('Erreur register : ' . $e->getMessage());
            return response()->json(['message' => 'Erreur serveur'], SERVER_ERROR);
        }
    }


    /**
     * @OA\Post(
     *     path="/api/logout",
     *     tags={"Authentification"},
     *     summary="Déconnexion",
     *     description="Déconnecte l'utilisateur courant",
     *     @OA\Response(response=204, description="Déconnexion réussie"),
     *     @OA\Response(response=500, description="Erreur serveur")
     * )
     */
    public function logout(Request $request)
    {
        try {
            $user = $request->user();

            if (!$user || !$user->currentAccessToken()) {
                return response()->json([
                    'message' => 'Aucun utilisateur connecté ou token introuvable.',
                ], NOT_FOUND);
            }

            $user->currentAccessToken()->delete();

            return response()->json(null, NO_CONTENT);

        } catch (QueryException $e) {
            Log::error('Erreur BDD (logout) : ' . $e->getMessage());
            return response()->json([
                'message' => 'Erreur base de données',
            ], SERVER_ERROR);
        } catch (\Exception $e) {
            Log::error('Erreur inconnue (logout) : ' . $e->getMessage());
            return response()->json([
                'message' => 'Erreur serveur',
            ], SERVER_ERROR);
        }
    }
}
