<?php

declare(strict_types=1);

/*
 * This file is part of the `informaticauco/oauth2-client-bundle`.
 *
 * Copyright (C) 2021 by Sergio Gómez <sergio@uco.es>
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Uco\OAuth2\ClientBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Uco\OAuth2\ClientBundle\DependencyInjection\UcoOAuth2ClientExtension;

final class UcoOAuth2ClientBundle extends Bundle
{
    public function getContainerExtension()
    {
        return $this->extension ?? new UcoOAuth2ClientExtension();
    }
}
