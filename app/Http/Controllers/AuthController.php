<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Traits\ApiResponser;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Hash;

class AuthController extends Controller
{
    use ApiResponser;

    public function register(Request $request)
    {
        $attr = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed'
        ]);

        $user = User::create([
            'name' => $attr['name'],
            'password' => bcrypt($attr['password']),
            'email' => $attr['email']
        ]);

        return $this->success([
            'token' => $user->createToken('API Token')->plainTextToken,
            'message' => 'User Registered'
        ]);
    }

    public function login(Request $request)
    {
        $attr = $request->validate([
            'email' => 'required|string|email|',
            'password' => 'required|string|min:6'
        ]);


        if (!Auth::attempt($attr)) {
            return $this->error('Credentials not match', 401);
        }

        return $this->success([
            'token' => auth()->user()->createToken('API Token')->plainTextToken,
             'status_code' => 200,  
              'token_type' => 'Bearer'
        ]);

    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Tokens Revoked'
        ];
    }

    // public function login(Request $request){  
    //         try {    
    //                 $request->validate([      'email' => 'email|required',      'password' => 'required'    ]);
    //                         $credentials = request(['email', 'password']);    
    //                         if (!Auth::attempt($credentials)) {      
    //                                 return response()->json([  'status_code' => 500,        'message' => 'Unauthorized'      ]); 
    //                             }    

    //                         $user = User::where('email', $request->email)->first();    
    //                         if ( ! Hash::check($request->password, $user->password, [])) {       
    //                             throw new \Exception('Error in Login');    
    //                         }    

    //                         $tokenResult = $user->createToken('authToken')->plainTextToken;   
    //                          return response()->json([      'status_code' => 200,      'access_token' => $tokenResult,      'token_type' => 'Bearer',    ]);
    //                 } 
    //                     catch (Exception $error) {   
    //                             return response()->json([  'status_code' => 500,     
    //                                                                     'message' => 'Error in Login',      'error' => $error,    ]);  
    //                         }
    // }
}