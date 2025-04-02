<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Critic;
use App\Models\User;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        $this->call([            
            LanguageSeeder::class,
            FilmSeeder::class,
            ActorSeeder::class,
            FilmActorSeeder::class
        ]);

		//Ne sera pas fait dans le cadre de ce TP, les users et les critiques seront créés par vous
        //User::factory(10)->has(Critic::factory(30))->create();
    }
}
