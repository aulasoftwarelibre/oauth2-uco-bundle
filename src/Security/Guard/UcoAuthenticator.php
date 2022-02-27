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

namespace AulaSoftwareLibre\OAuth2\ClientBundle\Security\Guard;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Messenger\Exception\HandlerFailedException;
use Symfony\Component\Messenger\HandleTrait;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use AulaSoftwareLibre\OAuth2\Client\Provider\UcoResourceOwner;
use AulaSoftwareLibre\OAuth2\ClientBundle\Message\AddUserMessage;

class UcoAuthenticator extends SocialAuthenticator
{
    use HandleTrait;
    use TargetPathTrait;

    private ClientRegistry $clientRegistry;
    private RouterInterface $router;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        MessageBusInterface $messageBus
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->messageBus = $messageBus;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request)
    {
        return 'connect_uco_check' === $request->attributes->get('_route');
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $userResource = $this
            ->getClient()
            ->fetchUserFromToken($credentials);
        \assert($userResource instanceof UcoResourceOwner);
        $userResourceId = $userResource->getId();

        try {
            $user = $userProvider->loadUserByUsername($userResourceId);
        } catch (UsernameNotFoundException $e) {
            $user = $this->createUser($userResourceId);
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new Response($message, Response::HTTP_FORBIDDEN);
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $homepagePath = $this->router->generate('homepage');
        if (!$request->getSession() instanceof Session) {
            return new RedirectResponse($homepagePath);
        }

        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
        if (!$targetPath) {
            return new RedirectResponse($homepagePath);
        }

        return new RedirectResponse($targetPath);
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, ?AuthenticationException $authException = null)
    {
        return new RedirectResponse(
            $this->router->generate('connect_uco_start'),
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }

    private function getClient(): OAuth2ClientInterface
    {
        return $this
            ->clientRegistry
            ->getClient('uco');
    }

    private function createUser(string $userResourceId): UserInterface
    {
        try {
            $user = $this->handle(new AddUserMessage($userResourceId));
        } catch (HandlerFailedException $e) {
            while ($e instanceof HandlerFailedException) {
                $e = $e->getPrevious();
            }

            throw $e;
        }

        return $user;
    }
}
