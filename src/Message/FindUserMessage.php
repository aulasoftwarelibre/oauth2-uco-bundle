<?php

declare(strict_types=1);

/*
 * This file is part of the `aulasoftwarelibre/oauth2-client-bundle`.
 *
 * Copyright (C) 2022 by Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AulaSoftwareLibre\OAuth2\ClientBundle\Message;

class FindUserMessage
{
    private string $username;

    public function __construct(string $username)
    {
        $this->username = $username;
    }

    public function getUsername(): string
    {
        return $this->username;
    }
}
