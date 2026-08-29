<?php

namespace EbicsApi\Ebics\Tests\Services;

use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Services\PsrHttpClient;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

class PsrHttpClientTest extends TestCase
{
    /**
     * @group psr-http-client-test-post
     */
    public function testPost(): void
    {
        $responseContent = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<ResponseTest/>\n";

        $stream = $this->createMock(StreamInterface::class);
        $streamFactory = $this->createMock(StreamFactoryInterface::class);
        $streamFactory->expects($this->atLeast(1))
            ->method('createStream')
            ->willReturn($stream);
        $stream->expects($this->atLeast(1))
            ->method('getContents')
            ->willReturn($responseContent);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->atLeast(1))
            ->method('getBody')
            ->willReturn($stream);

        $request = $this->createMock(RequestInterface::class);

        $request->expects($this->atLeast(1))
            ->method('withHeader')
            ->willReturn($request);
        $request->expects($this->atLeast(1))
            ->method('withBody')
            ->willReturn($request);
        $request->expects($this->atLeast(1))
            ->method('getHeaders')
            ->willReturn(['Content-Type' => ['text/xml; charset=UTF-8']]);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->atLeast(1))
            ->method('createRequest')
            ->willReturn($request);

        $client = new PsrHttpClient(
            $psrClient = new class($response) implements ClientInterface {
                /**
                 * @var RequestInterface
                 */
                public $request;

                /**
                 * @var ResponseInterface
                 */
                private $response;

                public function __construct(ResponseInterface $response)
                {
                    $this->response = $response;
                }

                public function sendRequest(RequestInterface $request): ResponseInterface
                {
                    $this->request = $request;
                    return $this->response;
                }
            },
            $requestFactory,
            $streamFactory
        );

        $request = new Request();
        $request->loadXML("<?xml version='1.0' encoding='utf-8'?><RequestTest/>");
        $response = $client->post('fake', $request);

        $this->assertEquals(
            $responseContent,
            $response->getContent()
        );
        $this->assertEquals(
            ['Content-Type' => ['text/xml; charset=UTF-8']],
            $psrClient->request->getHeaders()
        );
    }
}
