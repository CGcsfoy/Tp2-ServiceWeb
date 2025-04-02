<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class FilmFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        return [
            'title' => $this->faker->text(50),
            'release_year' => $this->faker->year(),
            'length' => $this->faker->numberBetween(100, 999),
            'description' => $this->faker->text(100),
            'rating' => $this->faker->text(5),
            'special_features' => $this->faker->text(200),
            'image' => $this->faker->text(40)
        ];
    }
}


