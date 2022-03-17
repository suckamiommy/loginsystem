<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Role;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Laravel\Passport\Client;

class AuthController extends Controller
{
    public array $validateFields = [
        'name' => ['required'],
        'email' => ['unique:users','required','email'],
        'password' => ['required','confirmed','min:8']
    ];

    public array $validateMessage = [
        'name.required' => 'Please fill in name.',
        'email.required' => 'Please fill in email.',
        'email.email' => 'Please fill in email.',
        'password.required' => 'Please fill in password.',
    ];

    public array $validateFieldsLogin = [
        'email' => ['required','email'],
        'password' => ['required','min:8']
    ];

    public array $validateMessageLogin = [
        'email.required' => 'Please fill in email.',
        'email.email' => 'Please fill in email.',
        'password.required' => 'Please fill in password.',
    ];

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), $this->validateFieldsLogin, $this->validateMessageLogin);

        if ($validator->fails()) {
            return response()->json($validator->messages(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $user = User::where('email', $request->email)->first();

        if($user){
            if(!Hash::check($request->password, $user->password)){
                return response()->json(["success" => false, "message" => 'Email or password is incorrect.'], 500);
            }
        }

        $user = User::where('email', $request->email)->where('email_verified_at', '<>', NULL)->first();

        if (!$user) {
            return [
                "response" => 'Email is not verified',
                "content" => ''
            ];
        }

        $passwordGrantClient = Client::where('password_client', 1)->first();

        $data = [
            'grant_type' => 'password',
            'client_id' => $passwordGrantClient->id,
            'client_secret' => $passwordGrantClient->secret,
            'username' => $request->email,
            'password' => $request->password,
            'scope' => '*'
        ];

        $tokenRequest = Request::create('/oauth/token', 'post', $data);

        $tokenResponse = app()->handle($tokenRequest);
        $contentString = $tokenResponse->content();
        $tokenContent = json_decode($contentString, true);

        if(!empty($tokenContent['access_token'])){
            return $tokenResponse;
        }

        if (empty($tokenContent)) {
            return response()->json([
                'message' => 'Email is not verified'
            ]);
        }

        return response()->json([
            'message' => 'Unauthenticated'
        ]);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), $this->validateFields, $this->validateMessage);

        if ($validator->fails()) {
            return response()->json($validator->messages(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $developerRole = Role::developer()->first();

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $user->roles()->attach($developerRole->id);

        $user->sendEmailVerificationNotification();

        if(!$user){
            return response()->json(["success" => false, "message" => 'Registration failed.'], 500);
        }

        return response()->json(["success" => true, "message" => 'Registration succeeded.'], 200);
    }
}
