<?php

namespace EbicsApi\Ebics\Tests;

use DateTime;
use EbicsApi\Ebics\Contexts\FDLContext;
use EbicsApi\Ebics\Contexts\FULContext;
use EbicsApi\Ebics\Exceptions\DebuggerException;
use EbicsApi\Ebics\Exceptions\InvalidUserOrUserStateException;
use EbicsApi\Ebics\Factories\DocumentFactory;
use EbicsApi\Ebics\Orders\FDL;
use EbicsApi\Ebics\Orders\FUL;
use EbicsApi\Ebics\Orders\HEV;
use EbicsApi\Ebics\Orders\HIA;
use EbicsApi\Ebics\Orders\HKD;
use EbicsApi\Ebics\Orders\HPB;
use EbicsApi\Ebics\Orders\INI;
use EbicsApi\Ebics\Services\ArrayLogger;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Silarhi\Cfonb\CfonbParser;

/**
 * Class EbicsClientTest.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
#[Group('ebics-client')]
class EbicsClientV24Test extends AbstractEbicsTestCase
{
    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('HEV')]
    #[Group('HEV-V24')]
    public function testHEV(int $credentialsId, array $codes): void
    {
        $logger = new ArrayLogger();
        $client = $this->setupClientV24($credentialsId, $codes['HEV']['fake'], false, $logger);
        $hev = $client->executeStandardOrder(new HEV())->getResponse();

        $infoRecords = $logger->recordsByLevel('info');
        self::assertCount(2, $infoRecords);
        self::assertEquals('start_standard_order', $infoRecords[0]['message']);
        self::assertEquals('HEV', $infoRecords[0]['context']['order_type']);
        self::assertEquals('complete_standard_order', $infoRecords[1]['message']);
        self::assertEquals('HEV', $infoRecords[1]['context']['order_type']);

        $responseHandler = $client->getResponseHandler();
        $code = $responseHandler->retrieveH000ReturnCode($hev);
        $reportText = $responseHandler->retrieveH000ReportText($hev);
        $this->assertResponseOk($code, $reportText);
    }

    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('HEV')]
    #[Group('HEV-V24')]
    public function testHEVDebug(int $credentialsId, array $codes): void
    {
        $client = $this->setupClientV24($credentialsId, $codes['HEV']['fake'], true);

        $this->expectException(DebuggerException::class);
        $client->executeStandardOrder(new HEV());
    }

    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('INI')]
    #[Group('INI-V24')]
    public function testINI(int $credentialsId, array $codes): void
    {
        $logger = new ArrayLogger();
        $client = $this->setupClientV24($credentialsId, $codes['INI']['fake'], false, $logger);

        // Check that keyring is empty and or wait on success or wait on exception.
        $userExists = $client->getKeyring()->getUserSignatureA();
        if ($userExists) {
            $this->expectException(InvalidUserOrUserStateException::class);
            $this->expectExceptionCode(91002);
        }
        $ini = $client->executeStandardOrder(new INI())->getResponse();
        if (!$userExists) {
            $infoRecords = $logger->recordsByLevel('info');
            self::assertCount(2, $infoRecords);
            self::assertEquals('start_standard_order', $infoRecords[0]['message']);
            self::assertEquals('INI', $infoRecords[0]['context']['order_type']);
            self::assertEquals('complete_standard_order', $infoRecords[1]['message']);

            $responseHandler = $client->getResponseHandler();
            $this->saveKeyring($credentialsId, $client->getKeyring());
            $code = $responseHandler->retrieveH00XReturnCode($ini);
            $reportText = $responseHandler->retrieveH00XReportText($ini);
            $this->assertResponseOk($code, $reportText);
        }
    }

    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('HIA')]
    #[Group('HIA-V24')]
    public function testHIA(int $credentialsId, array $codes): void
    {
        $logger = new ArrayLogger();
        $client = $this->setupClientV24($credentialsId, $codes['HIA']['fake'], false, $logger);

        // Check that keyring is empty and or wait on success or wait on exception.
        $bankExists = $client->getKeyring()->getUserSignatureX();
        if ($bankExists) {
            $this->expectException(InvalidUserOrUserStateException::class);
            $this->expectExceptionCode(91002);
        }
        $hia = $client->executeStandardOrder(new HIA())->getResponse();
        if (!$bankExists) {
            $infoRecords = $logger->recordsByLevel('info');
            self::assertCount(2, $infoRecords);
            self::assertEquals('start_standard_order', $infoRecords[0]['message']);
            self::assertEquals('HIA', $infoRecords[0]['context']['order_type']);
            self::assertEquals('complete_standard_order', $infoRecords[1]['message']);

            $responseHandler = $client->getResponseHandler();
            $this->saveKeyring($credentialsId, $client->getKeyring());
            $code = $responseHandler->retrieveH00XReturnCode($hia);
            $reportText = $responseHandler->retrieveH00XReportText($hia);
            $this->assertResponseOk($code, $reportText);
        }
    }

    /**
     * Run first HIA and Activate account in bank panel.
     *
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('HPB')]
    #[Group('HPB-V24')]
    public function testHPB(int $credentialsId, array $codes): void
    {
        $logger = new ArrayLogger();
        $client = $this->setupClientV24($credentialsId, $codes['HPB']['fake'], false, $logger);

        $this->assertExceptionCode($codes['HPB']['code']);

        $hpb = $client->executeInitializationOrder(new HPB());

        $infoRecords = $logger->recordsByLevel('info');
        self::assertGreaterThanOrEqual(2, count($infoRecords));
        self::assertEquals('start_initialization_order', $infoRecords[0]['message']);
        self::assertEquals('HPB', $infoRecords[0]['context']['order_type']);
        self::assertEquals('complete_initialization_order', end($infoRecords)['message']);

        $debugRecords = $logger->recordsByLevel('debug');
        self::assertNotEmpty($debugRecords);

        $responseHandler = $client->getResponseHandler();
        $code = $responseHandler->retrieveH00XReturnCode(
            $hpb->getTransaction()->getInitializationSegment()->getResponse()
        );
        $reportText = $responseHandler->retrieveH00XReportText(
            $hpb->getTransaction()->getInitializationSegment()->getResponse()
        );
        $this->assertResponseOk($code, $reportText);
        $this->saveKeyring($credentialsId, $client->getKeyring());
    }

    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('HKD')]
    #[Group('HKD-V24')]
    public function testHKD(int $credentialsId, array $codes): void
    {
        $client = $this->setupClientV24($credentialsId, $codes['HKD']['fake']);

        $this->assertExceptionCode($codes['HKD']['code']);
        $hkd = $client->executeDownloadOrder(new HKD());

        $responseHandler = $client->getResponseHandler();
        $code = $responseHandler->retrieveH00XReturnCode($hkd->getTransaction()->getLastSegment()->getResponse());
        $reportText = $responseHandler->retrieveH00XReportText($hkd->getTransaction()->getLastSegment()->getResponse());
        $this->assertResponseOk($code, $reportText);

        $code = $responseHandler->retrieveH00XReturnCode($hkd->getTransaction()->getReceipt());
        $reportText = $responseHandler->retrieveH00XReportText($hkd->getTransaction()->getReceipt());

        $this->assertResponseDone($code, $reportText);
    }

    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('FDL')]
    #[Group('FDL-V24')]
    public function testFDL(int $credentialsId, array $codes): void
    {
        foreach ($codes['FDL'] as $fileFormat => $code) {
            $logger = new ArrayLogger();
            $client = $this->setupClientV24($credentialsId, $code['fake'], false, $logger);

            $this->assertExceptionCode($code['code']);

            $context = FDLContext::resolveInstance()
                ->setFileFormat($fileFormat)
                ->setParameter('TEST', 'TRUE')
                ->setCountryCode('FR');

            $fdl = $client->executeDownloadOrder(
                new FDL(
                    $context,
                    new DateTime('2020-03-21'),
                    new DateTime('2020-04-21')
                )
            );

            $infoRecords = $logger->recordsByLevel('info');
            self::assertNotEmpty($infoRecords);
            self::assertEquals('start_download_order', $infoRecords[0]['message']);
            self::assertEquals('FDL', $infoRecords[0]['context']['order_type']);
            self::assertEquals('complete_download_order', end($infoRecords)['message']);

            $debugRecords = $logger->recordsByLevel('debug');
            self::assertNotEmpty($debugRecords);

            $parser = new CfonbParser();
            switch ($fileFormat) {
                case 'camt.xxx.cfonb120.stm':
                    $statements = $parser->read120C($fdl->getData());
                    self::assertNotEmpty($statements);
                    break;
                case 'camt.xxx.cfonb240.act':
                    $statements = $parser->read240C($fdl->getData());
                    self::assertNotEmpty($statements);
                    break;
            }

            $responseHandler = $client->getResponseHandler();
            $code = $responseHandler->retrieveH00XReturnCode($fdl->getTransaction()->getLastSegment()->getResponse());
            $reportText = $responseHandler->retrieveH00XReportText(
                $fdl->getTransaction()->getLastSegment()->getResponse()
            );
            $this->assertResponseOk($code, $reportText);

            $code = $responseHandler->retrieveH00XReturnCode($fdl->getTransaction()->getReceipt());
            $reportText = $responseHandler->retrieveH00XReportText($fdl->getTransaction()->getReceipt());

            $this->assertResponseDone($code, $reportText);
        }
    }

    /**
     * @param int $credentialsId
     * @param array $codes
     */
    #[DataProvider('serversDataProvider')]
    #[Group('FUL')]
    #[Group('FUL-V24')]
    public function testFUL(int $credentialsId, array $codes)
    {
        $documentFactory = new DocumentFactory();
        foreach ($codes['FUL'] as $fileFormat => $code) {
            $logger = new ArrayLogger();
            $client = $this->setupClientV24($credentialsId, $code['fake'], false, $logger);

            $this->assertExceptionCode($code['code']);

            $context = FULContext::resolveInstance()
                ->setFileFormat($fileFormat)
                ->setParameter('TEST', 'TRUE')
                ->setCountryCode('FR');

            $ful = $client->executeUploadOrder(
                new FUL(
                    $context,
                    $documentFactory->createXml($code['document'])
                )
            );

            $infoRecords = $logger->recordsByLevel('info');
            self::assertNotEmpty($infoRecords);
            self::assertEquals('start_upload_order', $infoRecords[0]['message']);
            self::assertEquals('FUL', $infoRecords[0]['context']['order_type']);
            self::assertEquals('complete_upload_order', end($infoRecords)['message']);

            $debugRecords = $logger->recordsByLevel('debug');
            self::assertNotEmpty($debugRecords);

            $responseHandler = $client->getResponseHandler();
            $code = $responseHandler->retrieveH00XReturnCode($ful->getTransaction()->getLastSegment()->getResponse());
            $reportText = $responseHandler->retrieveH00XReportText(
                $ful->getTransaction()->getLastSegment()->getResponse()
            );
            $this->assertResponseOk($code, $reportText);

            $code = $responseHandler->retrieveH00XReturnCode(
                $ful->getTransaction()->getInitialization()->getResponse()
            );
            $reportText = $responseHandler->retrieveH00XReportText(
                $ful->getTransaction()->getInitialization()->getResponse()
            );

            $this->assertResponseOk($code, $reportText);
        }
    }

    /**
     * Provider for servers.
     *
     * @return array<int, array{int, array}>
     */
    public static function serversDataProvider(): array
    {
        return [
            [
                9, // Credentials Id.
                [
                    'HEV' => ['code' => null, 'fake' => false],
                    'INI' => ['code' => null, 'fake' => false],
                    'HIA' => ['code' => null, 'fake' => false],
                    'HPB' => ['code' => null, 'fake' => false],
                    'HKD' => ['code' => null, 'fake' => false],
                    'FDL' => [
                        'camt.xxx.cfonb120.stm' => ['code' => '090005', 'fake' => false],
                        'camt.xxx.cfonb240.act' => ['code' => '090005', 'fake' => false],
                        'camt.xxx.estmt.eop' => ['code' => '090005', 'fake' => false],
                    ],
                    'FUL' => [
                        'pain.001.001.02.sct' => [
                            'code' => null,
                            'fake' => false,
                            'document' => '<?xml version="1.0" encoding="UTF-8"?><Root></Root>',
                        ],
                        'pain.008.001.02.sdd' => [
                            'code' => null,
                            'fake' => false,
                            'document' => '<?xml version="1.0" encoding="UTF-8"?><Root></Root>',
                        ],
                    ],
                ],
            ],
        ];
    }
}
