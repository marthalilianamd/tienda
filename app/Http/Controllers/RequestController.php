<?php

namespace App\Http\Controllers;


use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
use Psy\Exception\RuntimeException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use SoapVar;
use stdClass;
use SoapHeader;

class RequestController extends Controller
{
    const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

    public function getRequestPtp()
    {
        $request_ptp = array(
            'auth' => array(
                'login' =>  config('ptp.login'),
                'tranKey' => config('ptp.tranKey'),
                'nonce' => $this->getNonce(),
                'see' => $this->getSeed(),
        ));
        return $request_ptp;
    }

    public function doRequestPtp(){
        try {
            $jsonrequest = $this->getRequestPtp();
            print_r($jsonrequest);
            $header = array('Content-type:application/json; charset=utf-8');

            //header('content-type: application/json; charset=utf-8');
            $response = Http::withHeaders($header)->post(config('ptp.url'),$jsonrequest);
        }catch (HttpException $e){
            throw new HttpException('Falló el llamado POST ',$e);
        }
        print_r($response->json());
        if(!$response->ok()){
            throw new RuntimeException("Falló la petición : {$response}");
        }
        print_r('Petición exitosa!');
    }

    // nonce: Valor aleatorio para cada solicitud codificado en Base64.
    public function getNonce()
    {
        if (function_exists('random_bytes')) {
            try {
                $nonce = bin2hex(random_bytes(16));
            } catch (\Exception $e) {
            }
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $nonce = bin2hex(openssl_random_pseudo_bytes(16));
        } else {
            $nonce = mt_rand();
        }
        $nonce = base64_encode($nonce);

        return $nonce;
    }

    //Fecha actual, la cual se genera en formato ISO 8601.
    public function getSeed()
    {
        return date('c');
    }

    public function digest($encoded = true)
    {
        $digest = hash($this->algorithm, $this->getNonce(false) . $this->getSeed() . $this->tranKey(), true);
        //$digest = hash($this->algorithm, $this->getSeed() . $this->tranKey(), false);
        if ($encoded) {
            return base64_encode($digest);
        }
        return $digest;
    }

    /**
     * Parsea la entidad como un encabezado SOAP.
     * @return SoapHeader
     */
    public function asSoapHeader()
    {
        $UsernameToken = new stdClass();
        $UsernameToken->Username = new SoapVar(config('ptp.login'), XSD_STRING, null, self::WSSE, null, self::WSSE);
        $UsernameToken->Password = new SoapVar($this->digest(), XSD_STRING, 'PasswordDigest', null, 'Password', self::WSSE);
        $UsernameToken->Nonce = new SoapVar($this->getNonce(), XSD_STRING, null, self::WSSE, null, self::WSSE);
        $UsernameToken->Created = new SoapVar($this->getSeed(), XSD_STRING, null, self::WSU, null, self::WSU);

        $security = new stdClass();
        $security->UsernameToken = new SoapVar($UsernameToken, SOAP_ENC_OBJECT, null, self::WSSE, 'UsernameToken', self::WSSE);

        return new SoapHeader(self::WSSE, 'Security', $security, true);
    }

}
