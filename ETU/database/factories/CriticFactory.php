<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class CriticFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        return [
            'score' => $this->faker->randomFloat(1, 0, 100),
            'comment' => $this->faker->text(100),
            'film_id' => $this->faker->numberBetween(1,100)
        ];
    }
}

//filmfactory
//actorfilmfactory