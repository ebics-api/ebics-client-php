<?php

namespace EbicsApi\Ebics\Tests\Handlers;

use EbicsApi\Ebics\Factories\CertificateX509Factory;
use EbicsApi\Ebics\Factories\Crypt\BigIntegerFactory;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Factories\EbicsFactoryV25;
use EbicsApi\Ebics\Factories\SignatureFactory;
use EbicsApi\Ebics\Handlers\OrderDataHandler;
use EbicsApi\Ebics\Handlers\Traits\H004Trait;
use EbicsApi\Ebics\Handlers\Traits\H00XTrait;
use EbicsApi\Ebics\Models\GenericOrderData;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\Processor\AESEncryptor;
use EbicsApi\Ebics\Services\Processor\Base64Encoder;
use EbicsApi\Ebics\Services\RandomService;
use EbicsApi\Ebics\Services\TransactionKeyResolver;
use EbicsApi\Ebics\Tests\AbstractEbicsTestCase;

/**
 * Class RequestFactoryTest.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 *
 * @group order-data-handler
 */
class OrderDataHandlerTest extends AbstractEbicsTestCase
{
    use H00XTrait;
    use H004Trait;

    /**
     * @var OrderDataHandler
     */
    private $orderDataHandler;

    public function setUp(): void
    {
        parent::setUp();
        $client = $this->setupClientV25(3);
        $this->setupKeys($client->getKeyring());
        $ebicsFactory = new EbicsFactoryV25();
        $aesEncryptor = new AESEncryptor(new TransactionKeyResolver());
        $this->orderDataHandler = $ebicsFactory->createOrderDataHandler(
            new Base64Encoder(),
            $client->getUser(),
            $client->getKeyring(),
            new CryptService(new RSAFactory($aesEncryptor), $aesEncryptor, new RandomService, new Base64Encoder),
            new SignatureFactory(new RSAFactory($aesEncryptor)),
            new CertificateX509Factory(),
            new BigIntegerFactory()
        );
    }

    /**
     * @group HandleINI
     */
    public function testHandleINI()
    {
        $h00x = $this->getH00XVersion();
        $ini = file_get_contents($this->fixtures.'/ini.xml');
        $iniXML = new Request();
        $iniXML->loadXML($ini);
        $iniXPath = $this->prepareH00XXPath($iniXML);
        $orderData = $iniXPath->query("//$h00x:body/$h00x:DataTransfer/$h00x:OrderData")->item(0)->nodeValue;
        $orderDataDeUn = gzuncompress(base64_decode($orderData));
        $orderDataXML = new GenericOrderData();
        $orderDataXML->loadXML($orderDataDeUn);
        $orderDataXPath = $this->prepareS001XPath($orderDataXML);
        $iniDatetime = $orderDataXPath->query("//S001:SignaturePubKeyInfo/S001:PubKeyValue/S001:TimeStamp")->item(0)->nodeValue;
        self::assertNotEmpty($iniDatetime);
    }
}
