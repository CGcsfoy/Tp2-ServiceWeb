<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;
use Laravel\Sanctum\Sanctum;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_allows_up_to_5_login_requests_per_minute_with_the_throttling()
    {
        User::create([
            'login' => 'jane.doe',
            'first_name' => 'Jane',
            'last_name' => 'Doe',
            'email' => 'jane.doe@example.com',
            'password' => bcrypt('securepass'),
        ]);

        for ($i = 1; $i <= 5; $i++) {
            $response = $this->postJson('/api/signin', [
                'login' => 'jane.doe',
                'password' => 'securepass'
            ]);
            $response->assertStatus(OK);
        }
    }

    /** @test */
    public function test_login_successfully()
    {
        User::create([
            'login' => 'jane.doe',
            'first_name' => 'Jane',
            'last_name' => 'Doe',
            'email' => 'jane.doe@example.com',
            'password' => bcrypt('securepass'),
        ]);

        $response = $this->postJson('/api/signin', [
            'login' => 'jane.doe',
            'password' => 'securepass',
        ]);

        $response->assertStatus(OK)
                 ->assertJsonStructure([
                     'message',
                     'access_token',
                     'user' => ['login', 'email', 'first_name', 'last_name']
                 ]);
    }

    /** @test */
    public function test_blocks_the_6th_login_attempt_due_to_throttling()
    {
        User::create([
            'login' => 'jane.doe',
            'first_name' => 'Jane',
            'last_name' => 'Doe',
            'email' => 'jane.doe@example.com',
            'password' => bcrypt('securepass'),
        ]);

        for ($i = 0; $i < 6; $i++) {
            $response = $this->postJson('/api/signin', [
                'login' => 'jane.doe',
                'password' => 'securepass',
            ]);
            $response->assertStatus(OK);
        }

        $response = $this->postJson('/api/signin', [
            'login' => 'jane.doe',
            'password' => 'securepass',
        ]);

        $response->assertStatus(TOO_MANY_REQUEST);
    }

    /** @test */
    public function test_register_successfully()
    {
        $response = $this->postJson('/api/signup', [
            'login' => 'john.doe',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => 'john@example.com',
            'email_confirmation' => 'john@example.com',
            'password' => 'securepass',
            'password_confirmation' => 'securepass',
        ]);

        $response->assertStatus(CREATED)
                 ->assertJsonStructure([
                     'message',
                     'user' => ['login', 'email', 'first_name', 'last_name']
                 ]);
    }

    /** @test */
    public function test_register_fails_if_email_already_exists()
    {
        User::create([
            'login' => 'john.doe',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => 'john@example.com',
            'password' => bcrypt('securepass'),
        ]);

        $response = $this->postJson('/api/signup', [
            'login' => 'johnny.d',
            'first_name' => 'Johnny',
            'last_name' => 'D',
            'email' => 'john@example.com',
            'email_confirmation' => 'john@example.com',
            'password' => 'securepass',
            'password_confirmation' => 'securepass',
        ]);

        $response->assertStatus(INVALID_DATA);
    }

    /** @test */
    public function test_logout_successfully()
    {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $response = $this->postJson('/api/signout');

        $response->assertNoContent();
    }

    /** @test */
    public function test_logout_fails_without_token()
    {
        $response = $this->postJson('/api/signout');
        $response->assertStatus(UNAUTHORIZED);
    }
}
