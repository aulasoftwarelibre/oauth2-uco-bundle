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

namespace AulaSoftwareLibre\OAuth2\ClientBundle;

use AulaSoftwareLibre\OAuth2\ClientBundle\DependencyInjection\UcoOAuth2ClientExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class UcoOAuth2ClientBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return $this->extension ?? new UcoOAuth2ClientExtension();
    }
}
