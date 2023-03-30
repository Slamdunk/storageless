<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

declare(strict_types=1);

namespace PSR7SessionsTest\Storageless\Http\ClientFingerprint;

use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration;
use PSR7Sessions\Storageless\Http\ClientFingerprint\SameOriginRequest;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Source;

/** @covers \PSR7Sessions\Storageless\Http\ClientFingerprint\SameOriginRequest */
final class SameOriginRequestTest extends TestCase
{
    private Source $source;
    private Configuration $configuration;
    private ServerRequest $request;
    private SameOriginRequest $constraint;

    protected function setUp(): void
    {
        $this->source        = new class implements Source {
            public function extractFrom(ServerRequestInterface $request): string
            {
                return $request->getMethod();
            }
        };
        $this->configuration = new Configuration(true, $this->source);
        $this->request       = new ServerRequest(method: 'GET');
        $this->constraint    = new SameOriginRequest($this->configuration, $this->request);
    }

    public function testWhenDisabledTheTokenIsAlwaysValid(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::never())->method('getMethod');

        $constraint = new SameOriginRequest(
            new Configuration(
                false,
                $this->source,
            ),
            $request,
        );

        $constraint->assert($this->createMock(Token::class));
    }

    public function testShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $this->constraint->assert($this->createMock(Token::class));
    }

    public function testShouldRaiseExceptionWhenClaimIsAbsent(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('"Client Fingerprint" claim missing');

        $this->constraint->assert($this->buildToken());
    }

    public function testShouldRaiseExceptionWhenFingerprintDoesNotMatch(): void
    {
        $token = $this->buildToken([SameOriginRequest::CLAIM_FINGERPRINT => 'POST']);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('"Client Fingerprint" does not match');

        $this->constraint->assert($token);
    }

    /** @param array<non-empty-string, mixed> $claims */
    private function buildToken(
        array $claims = [],
    ): Plain {
        return new Plain(
            new DataSet([], ''),
            new DataSet($claims, ''),
            new Signature('sig+hash', 'sig+encoded'),
        );
    }
}
