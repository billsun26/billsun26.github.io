<?php

namespace Sce\AccountCreatorBundle\Controller;

use Guzzle\Http\Exception\BadResponseException;
use Sce\AccountCreatorBundle\Entity\Account;
use Sce\BaseBundle\Controller\Controller;
use Sce\BaseBundle\Exception\ValidationException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;

/**
 * *******************************************
 * Documentation about 4 relevant services
 * *******************************************
 *
 * ===================
 * AccountDataService
 * ===================
 * Url:
 *   172.17.8.101:49280
 *
 * Response:
 *   If response status code is 400, it's a bad request, and it means validation of fields failed.
 *
 * Description:
 *   This service is responsible for reading, creating, updating, removing accounts. It validates accounts at data level
 * before they are persisted in the db.
 *
 *
 * =========================
 * EmailConfirmationService
 * =========================
 * Url:
 *  172.17.8.101:49281
 *
 * Description:
 *  This service is responsible for generating email confirmation token and sending out confirmation email immediately.
 *
 *
 * =======================
 * AccountPasswordService
 * =======================
 * Url:
 *  172.17.8.101:49282
 *
 * Response:
 *   If response status code is 400, it's a bad request, and it means validation of fields failed.
 *
 * Description:
 *   This service contains password validators that make sure the user supplied passwords conform to business rules.
 * For instance, the new password is significantly different from the previous password, the new password does not
 * contain user details, etc.
 *
 *
 * ===================
 * EmailFormatService
 * ===================
 * Url:
 *   172.17.8.101:49283
 *
 * Response:
 *   If response status code is 400, it's a bad request, and it means validation of fields failed.
 *
 * Description:
 *   This service checks that an email address is with valid format by regex: \b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b
 *
 *
 *
 * *************************
 * Class AccountCreateController
 * *************************
 *
 * This class is a Symfony controller that is responsible to create an account. It encapsulates the workflow for account
 * creation, include validating form fields, persisting accounts, and sending out notifications upon successful account
 * creation.
 *
 * The exceptions below will be caught by Symfony's event listener ,and handled handled nicely:
 *
 *      Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException
 *
 *
 * @package Sce\AccountCreatorBundle\Controller
 */
class AccountCreateController extends Controller
{
    // Defined endpoints used by the controller
    const ACCOUNT_CREATE_ENDPOINT = "http://172.17.8.101:49280/account/create_account";
    const ENDPOINT_TO_SEND_EMAIL_CONFIRMATION = "http://172.17.8.101:49281/accounts/account";
    const PASSWORD_ENDPOINT = "http://172.17.8.101:49282/password/check";
    const EMAIL_FORMAT_CHECKING_ENDPOINT = "http://172.17.8.101:49283/check";

    /**
     * @var Stores all the validation error messages
     */
    protected $validation_errors;

    /**
     * This action handles account creation request from a web form. It encapsulated the workflow required to create
     * an account.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @throws \Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function createAction(Request $request)
    {
        if ($this->validateRequest($request)) {
            // Make an HTTP request to AccountDataService to persist an account
            $httpClient = new Client();
            $requestData = array(
                'full_name' => $request->get('full_name'),
                'email'     => $request->get('email'),
                'password'  => $request->get('password')
            );
            $createAccountRequest = $httpClient->createRequest('POST', self::ACCOUNT_CREATE_ENDPOINT, $requestData);
            $createAccountRequest = self::getSignatureGeneratorAndSignRequest($createAccountRequest, '123456');

            try {
                $response = $createAccountRequest->send();

                $accountData = json_decode($response->getBody(true), true);

                // Validation errors are present
                if ($response->getStatusCode() == 400 || !is_array($accountData)) {
                    return new JsonResponse($accountData, $httpStatusCode = 404);
                }

                // Makes HTTP request to EmailConfirmationService to send out the confirmation email immediately.
                $account = new Account();
                $account->setId($accountData['id']);
                $account->setEmail($accountData['email']);
                $account->setFullName($accountData['full_name']);

                $httpClient = new Client();
                $requestData = array(
                    'account' => $account->getId(),
                );
                $emailConfirmationRequest = $httpClient->createRequest('POST', self::ENDPOINT_TO_SEND_EMAIL_CONFIRMATION, $requestData);
                $emailConfirmationRequest = self::getSignatureGeneratorAndSignRequest($emailConfirmationRequest, '123456');

                try {
                    $emailConfirmationRequest->send();
                } catch (BadResponseException $e) {
                    $this->get('logger')->error('Could not send confirmation email.');
                } catch (\Exception $e) {
                    $this->get('logger')->error('Could not send confirmation email.');
                }

                return $this->handleView(json_decode($response->getBody(true), true), $httpStatusCode = 200);

            } catch (BadResponseException $e) {
                $this->get('logger')->error('Could not create an account.');
                throw new ServiceUnavailableHttpException(30, 'Could not create an account.');
            } catch (\Exception $e) {
                $this->get('logger')->error('Could not create an account.');
                throw new ServiceUnavailableHttpException(30, 'Could not create an account');
            }

        } else {
            // Handles the errors and presents the user with the error messages
            return $this->handleFormErrors($this->validation_errors);
        }
    }

    /**
     * Deletes the account from database.
     *
     * @param \Sce\AccountDataBundle\Entity\Account $account
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function removeAccountAction(Account $account)
    {
        $entityManager = $this->get('doctrine.orm.entity_manager');
        $entityManager->remove($account);
        $entityManager->flush();

        return $this->handleView(
            [
                'success' => true,
                'id'      => $account->getId()
            ]
        );
    }

    /**
     * @param Request $request
     * @return void
     *
     * @throw ServiceUnavailableHttpException
     * @throw ValidationException
     */
    public function validateRequest(Request $request)
    {
        $this->validation_errors = array();

        // Check that all required arguments are sent in the request
        if (!$request->get('full_name') || !$request->get('email') || !$request->get('password')) {
            $this->validation_errors['all'] = "Not enough arguments specified.";
        }

        // Validate the email address
        $email = $request->get('email');
        if (strpos($email, '@') === false) {
            $this->validation_errors['email'] = "Invalid email address";
        }
        if ($this->isEmailDomainInBlackList($email)) {
            $this->validation_errors['email'] = "Invalid email address";
        }

        $httpClient = new Client();
        $requestData = array(
            'email' => $email
        );
        $emailFormatCheckingRequest = $httpClient->createRequest('POST', self::EMAIL_FORMAT_CHECKING_ENDPOINT, $requestData);
        $emailFormatCheckingRequest = self::getSignatureGeneratorAndSignRequest($emailFormatCheckingRequest, '123456');
        try {
            $emailFormatCheckingResponse = $emailFormatCheckingRequest->send();

            if ($emailFormatCheckingResponse->getStatusCode() == 400) {
                $this->validation_errors['email'] = "Invalid email address";
            }

        } catch (BadResponseException $e) {
            $this->get('logger')->error('Could not check email format.');
            throw new ValidationException(30, 'Could not check email format.');
        } catch (\Exception $e) {
            $this->get('logger')->error('Could not check password.');
            throw new ValidationException(30, 'Could not check email format.');
        }


        // Make an HTTP request to AccountPassword service to validate the supplied password against business policies.
        $password = $request->get('password');
        $keywordBlacklist = [
            $email,
            $password
        ];

        $httpClient = new Client();
        $requestData = array(
            'account' => 0,
            'new_password'     => $password,
            'keyword_blacklist' => implode(' ', $keywordBlacklist)
        );
        $passwordCheckingRequest = $httpClient->createRequest('POST', self::PASSWORD_ENDPOINT, $requestData);
        $passwordCheckingRequest = self::getSignatureGeneratorAndSignRequest($passwordCheckingRequest, '123456');

        try {
            $checkPasswordResponse = $passwordCheckingRequest->send();

            if ($checkPasswordResponse->getStatusCode() == 400) {
                $this->validation_errors['password'] = json_decode($checkPasswordResponse->getBody(true), true);
            }

        } catch (BadResponseException $e) {
            $this->get('logger')->error('Could not check password.');
            throw new ServiceUnavailableHttpException(30, 'Could not check password.');
        } catch (\Exception $e) {
            $this->get('logger')->error('Could not check password.');
            throw new ServiceUnavailableHttpException(30, 'Could not check password.');
        }
    }

    /**
     * Checks if the email domain is in the blacklist.
     *
     * @param $email
     * @return boolean
     */
    private function isEmailDomainInBlackList($email) {
        list(, $domain) = explode('@', $email);
        $result = false;
        if (in_array(strtolower($domain), array('example.com'))) {
            $result = true;
        } else if (stripos($domain, '.scee')) {
            $result = true;
        } else if (stripos($domain, 'test.')) {
            $result = true;
        } else if (stripos($domain, 'demo.')) {
            $result = true;
        } else if (stripos($domain, 'developer.')) {
            $result = true;
        } else if (stripos($domain, 'testing.')) {
            $result = true;
        }
        return $result;
    }

    /**
     * Gets the signature generator and signs the HTTP request with shared security.
     *
     * @param $request
     * @param $apiKey
     * @return mixed
     */
    public static function getSignatureGeneratorAndSignRequest(&$request, $apiKey) {
        $encoderRegistry = new EncoderRegistry();
        $encoder = new Encoder();
        $encoderRegistry->addEncoder($encoder);
        $signatureGenerator = new Generator($encoderRegistry);

        $signatureContext = APIRequestSignatureContextFactory::buildFromRequest(
            $request,
            $apiKey
        );
        $signatureContext = $signatureGenerator->generate($signatureContext);

        $request->addHeader('X-Authz', 'TEST ' . sprintf(
                '%s:%s',
                $signatureContext->getSignature(),
                $signatureContext->getMicrotime()
            ));
        return $request;
    }
}
