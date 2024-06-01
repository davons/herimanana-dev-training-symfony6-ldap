<?php

namespace App\EventListener;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Ldap\Security\LdapUser;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

class LdapLoginListener
{
    /**
     * @param EntityManagerInterface $manager
     * @param UserPasswordHasherInterface $passwordHasher
     * @param UserRepository $userRepository
     */
    public function __construct(
        private readonly EntityManagerInterface $manager,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly UserRepository $userRepository
    ){
    }

    /**
     * @param InteractiveLoginEvent $event
     * @return void
     */
    public function onSuccessLogin(InteractiveLoginEvent $event): void
    {
        $userLdap = $event->getAuthenticationToken()->getUser();

        if ($userLdap instanceof LdapUser) {

            $username = $event->getRequest()->get('_username');
            $plainPassword = $event->getRequest()->get('_password');

            $existingUser = $this->userRepository->findOneBy(['email' => $username]);

            if (null === $existingUser) {
                $user = new User();
                $email = $userLdap->getEntry()->getAttributes()['mail'][0];
                $user->setEmail($email);
                $user->setRoles(['ROLE_USER']);

                // Set other necessary user attributes here
                $user->setPassword(
                    $this->passwordHasher->hashPassword($user, $plainPassword)
                );

                $user->setLastLoginAt(new \DateTimeImmutable('now'));

                $this->manager->persist($user);

            } else {
                $existingUser->setLastLoginAt(new \DateTimeImmutable('now'));
            }

            $this->manager->flush();
        }

    }
}