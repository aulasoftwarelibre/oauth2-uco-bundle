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

namespace Uco\OAuth2\ClientBundle\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

final class SecurityController extends AbstractController
{
    use TargetPathTrait;

    private ClientRegistry $clientRegistry;

    public function __construct(ClientRegistry $clientRegistry)
    {
        $this->clientRegistry = $clientRegistry;
    }

    public function check(): void
    {
        throw new \RuntimeException('This method should not be called.');
    }

    public function start(Request $request): Response
    {
        $this->storeTargetPath($request);

        return $this->clientRegistry
            ->getClient('uco')
            ->redirect(['openid'], []);
    }

    private function storeTargetPath(Request $request): void
    {
        $targetPath = $request->query->get('_target_path');
        $session = $request->getSession();

        if (!$targetPath || !$session instanceof SessionInterface || !$request->hasSession()) {
            return;
        }

        $this->saveTargetPath($session, 'main', $targetPath);
    }
}
