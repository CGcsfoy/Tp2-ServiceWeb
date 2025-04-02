<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;
use App\Http\Resources\CriticResource;
use App\Http\Resources\FilmActorResource;
use App\Http\Resources\LanguageResource;

class FilmResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array|\Illuminate\Contracts\Support\Arrayable|\JsonSerializable
     */
    public function toArray($request)
    {
        return
        [
          
            'title' => $this->title,
            'release_year' => $this->release_year,
            'length' => $this->length,
            'description' => $this->description,
            'rating' => $this->rating,
            'special_features' => $this->special_features,
            'image' => $this->image,
            'language_id' => $this->language_id
        ];
    }
}
