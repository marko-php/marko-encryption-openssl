<?php

declare(strict_types=1);

use Marko\Encryption\Config\EncryptionConfig;
use Marko\Encryption\Contracts\EncryptorInterface;
use Marko\Encryption\Exceptions\DecryptionException;
use Marko\Encryption\Exceptions\EncryptionException;
use Marko\Encryption\OpenSsl\OpenSslEncryptor;
use Marko\Testing\Fake\FakeConfigRepository;

/**
 * @param list<string> $previousKeys
 */
function createTestEncryptionConfig(
    string $key = '',
    string $cipher = 'aes-256-gcm',
    array $previousKeys = [],
    bool $aadFallback = true,
): EncryptionConfig {
    if ($key === '') {
        $key = base64_encode(random_bytes(32));
    }

    $repository = new FakeConfigRepository([
        'encryption.key' => $key,
        'encryption.cipher' => $cipher,
        'encryption.previous_keys' => $previousKeys,
        'encryption.aad_fallback' => $aadFallback,
    ]);

    return new EncryptionConfig($repository);
}

describe('OpenSslEncryptor', function (): void {
    it('implements EncryptorInterface', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());

        expect($encryptor)->toBeInstanceOf(EncryptorInterface::class);
    });

    it('encrypts string value', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $plaintext = 'Hello, World!';

        $encrypted = $encryptor->encrypt($plaintext);

        expect($encrypted)->not->toBe($plaintext)
            ->and($encrypted)->toBeString()
            ->and($encrypted)->not->toBeEmpty();
    });

    it('decrypts back to original value', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $plaintext = 'Hello, World!';

        $encrypted = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    it('produces different ciphertext for same plaintext', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $plaintext = 'Same text';

        $encrypted1 = $encryptor->encrypt($plaintext);
        $encrypted2 = $encryptor->encrypt($plaintext);

        expect($encrypted1)->not->toBe($encrypted2);
    });

    it('encrypts and decrypts empty string', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());

        $encrypted = $encryptor->encrypt('');
        $decrypted = $encryptor->decrypt($encrypted);

        expect($decrypted)->toBe('');
    });

    it('encrypts and decrypts long text', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $plaintext = str_repeat('A long piece of text. ', 50);

        $encrypted = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext)
            ->and(strlen($plaintext))->toBeGreaterThan(1000);
    });

    it('encrypts and decrypts unicode text', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $plaintext = 'Привет мир! 你好世界! こんにちは世界!';

        $encrypted = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    it('throws DecryptionException for tampered ciphertext', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret data');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        $payload['value'] = base64_encode('tampered');
        $tampered = base64_encode(json_encode($payload));

        $encryptor->decrypt($tampered);
    })->throws(DecryptionException::class);

    it('throws DecryptionException for invalid base64', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());

        $encryptor->decrypt('not-valid-base64!!!');
    })->throws(DecryptionException::class);

    it('throws DecryptionException for wrong key', function (): void {
        $key1 = base64_encode(random_bytes(32));
        $key2 = base64_encode(random_bytes(32));

        $encryptor1 = new OpenSslEncryptor(createTestEncryptionConfig(key: $key1));
        $encryptor2 = new OpenSslEncryptor(createTestEncryptionConfig(key: $key2));

        $encrypted = $encryptor1->encrypt('secret data');

        $encryptor2->decrypt($encrypted);
    })->throws(DecryptionException::class);

    it('throws EncryptionException for invalid key', function (): void {
        new OpenSslEncryptor(createTestEncryptionConfig(key: 'not-valid-base64'));
    })->throws(EncryptionException::class, 'Invalid encryption key');

    it('throws EncryptionException for key with wrong length', function (): void {
        $shortKey = base64_encode(random_bytes(16));

        new OpenSslEncryptor(createTestEncryptionConfig(key: $shortKey));
    })->throws(EncryptionException::class, 'Invalid encryption key');

    it('throws EncryptionException at construction when the configured cipher is not AEAD', function (): void {
        new OpenSslEncryptor(createTestEncryptionConfig(cipher: 'aes-256-cbc'));
    })->throws(EncryptionException::class);

    it(
        'throws EncryptionException at construction when the configured cipher is unknown to openssl',
        function (): void {
            new OpenSslEncryptor(createTestEncryptionConfig(cipher: 'not-a-real-cipher'));
        },
    )->throws(EncryptionException::class);

    it('constructs successfully with the default aes-256-gcm cipher', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig(cipher: 'aes-256-gcm'));

        expect($encryptor)->toBeInstanceOf(OpenSslEncryptor::class);
    });

    it('throws DecryptionException invalidPayload when a payload field is not a string', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        $payload['iv'] = 12345;
        $tampered = base64_encode(json_encode($payload));

        $encryptor->decrypt($tampered);
    })->throws(DecryptionException::class);

    it('throws DecryptionException invalidPayload when a required payload field is missing', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        unset($payload['tag']);
        $tampered = base64_encode(json_encode($payload));

        $encryptor->decrypt($tampered);
    })->throws(DecryptionException::class);

    it('round-trips encrypt then decrypt with the default AEAD cipher', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig(cipher: 'aes-256-gcm'));
        $plaintext = 'Hello AEAD world!';

        $decrypted = $encryptor->decrypt($encryptor->encrypt($plaintext));

        expect($decrypted)->toBe($plaintext);
    });

    it('throws DecryptionException rather than a TypeError for a crafted non-string iv', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        $payload['iv'] = ['not', 'a', 'string'];
        $tampered = base64_encode(json_encode($payload));

        $encryptor->decrypt($tampered);
    })->throws(DecryptionException::class);

    it('rejects a payload whose GCM auth tag is truncated to one byte', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        $tag = base64_decode($payload['tag'], true);
        $payload['tag'] = base64_encode($tag[0]);
        $tampered = base64_encode(json_encode($payload));

        $encryptor->decrypt($tampered);
    })->throws(DecryptionException::class, 'Authentication tag must be 16 bytes, got 1');

    it('rejects a forged ciphertext paired with a brute-forced one-byte tag', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        $value = base64_decode($payload['value'], true);
        $value[0] = chr(ord($value[0]) ^ 0x01);
        $payload['value'] = base64_encode($value);

        $forged = null;

        for ($byte = 0; $byte < 256; $byte++) {
            $payload['tag'] = base64_encode(chr($byte));

            try {
                $forged = $encryptor->decrypt(base64_encode(json_encode($payload)));
                break;
            } catch (DecryptionException) {
                continue;
            }
        }

        expect($forged)->toBeNull();
    });

    it('rejects a payload whose IV length does not match the cipher IV length', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $json = base64_decode($encrypted, true);
        $payload = json_decode($json, true);
        $payload['iv'] = base64_encode(random_bytes(8));
        $tampered = base64_encode(json_encode($payload));

        $encryptor->decrypt($tampered);
    })->throws(DecryptionException::class, 'Initialization vector must be 12 bytes, got 8');

    it('still round-trips a valid payload with a full-length tag and IV', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());
        $encrypted = $encryptor->encrypt('secret');

        $payload = json_decode(base64_decode($encrypted, true), true);

        expect(strlen(base64_decode($payload['tag'], true)))->toBe(16)
            ->and(strlen(base64_decode($payload['iv'], true)))->toBe(12)
            ->and($encryptor->decrypt($encrypted))->toBe('secret');
    });

    it('accepts a 16-byte key for aes-128-gcm and round-trips', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig(
            key: base64_encode(random_bytes(16)),
            cipher: 'aes-128-gcm',
        ));

        expect($encryptor->decrypt($encryptor->encrypt('secret')))->toBe('secret');
    });

    it('rejects a 32-byte key for aes-128-gcm instead of silently truncating it', function (): void {
        new OpenSslEncryptor(createTestEncryptionConfig(
            key: base64_encode(random_bytes(32)),
            cipher: 'aes-128-gcm',
        ));
    })->throws(EncryptionException::class, 'Invalid encryption key');

    it('names the cipher and required key length when the key length is wrong', function (): void {
        $exception = null;

        try {
            new OpenSslEncryptor(createTestEncryptionConfig(
                key: base64_encode(random_bytes(32)),
                cipher: 'aes-128-gcm',
            ));
        } catch (EncryptionException $e) {
            $exception = $e;
        }

        expect($exception)->toBeInstanceOf(EncryptionException::class)
            ->and($exception->getContext())->toContain('16-byte')
            ->and($exception->getContext())->toContain('aes-128-gcm')
            ->and($exception->getSuggestion())->toContain('random_bytes(16)');
    });

    it('round-trips a value encrypted with associated data', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());

        $encrypted = $encryptor->encrypt('123-45-6789', 'users.ssn');

        expect($encryptor->decrypt($encrypted, 'users.ssn'))->toBe('123-45-6789');
    });

    it('rejects ciphertext swapped into a field with different associated data', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());

        $encrypted = $encryptor->encrypt('123-45-6789', 'users.ssn');

        $encryptor->decrypt($encrypted, 'users.nickname');
    })->throws(DecryptionException::class);

    it('rejects ciphertext with associated data when decrypted without it', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig());

        $encrypted = $encryptor->encrypt('secret', 'users.ssn');

        $encryptor->decrypt($encrypted);
    })->throws(DecryptionException::class);

    it('decrypts legacy ciphertext without associated data when aad_fallback is on', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig(aadFallback: true));

        $legacy = $encryptor->encrypt('secret');

        expect($encryptor->decrypt($legacy, 'users.ssn'))->toBe('secret');
    });

    it('rejects legacy ciphertext without associated data when aad_fallback is off', function (): void {
        $encryptor = new OpenSslEncryptor(createTestEncryptionConfig(aadFallback: false));

        $legacy = $encryptor->encrypt('secret');

        $encryptor->decrypt($legacy, 'users.ssn');
    })->throws(DecryptionException::class);

    it('decrypts ciphertext written with a previous key', function (): void {
        $oldKey = base64_encode(random_bytes(32));
        $old = new OpenSslEncryptor(createTestEncryptionConfig(key: $oldKey));
        $rotated = new OpenSslEncryptor(createTestEncryptionConfig(previousKeys: [$oldKey]));

        expect($rotated->decrypt($old->encrypt('secret')))->toBe('secret')
            ->and($rotated->decrypt($old->encrypt('secret', 'users.ssn'), 'users.ssn'))->toBe('secret');
    });

    it('decrypts legacy ciphertext from a previous key via aad_fallback', function (): void {
        $oldKey = base64_encode(random_bytes(32));
        $old = new OpenSslEncryptor(createTestEncryptionConfig(key: $oldKey));
        $rotated = new OpenSslEncryptor(createTestEncryptionConfig(previousKeys: [$oldKey]));

        expect($rotated->decrypt($old->encrypt('secret'), 'users.ssn'))->toBe('secret');
    });

    it('encrypts with the current key only, never a previous key', function (): void {
        $oldKey = base64_encode(random_bytes(32));
        $old = new OpenSslEncryptor(createTestEncryptionConfig(key: $oldKey));
        $rotated = new OpenSslEncryptor(createTestEncryptionConfig(previousKeys: [$oldKey]));

        $old->decrypt($rotated->encrypt('secret'));
    })->throws(DecryptionException::class);

    it('rejects ciphertext from a key that is neither current nor previous', function (): void {
        $stranger = new OpenSslEncryptor(createTestEncryptionConfig());
        $rotated = new OpenSslEncryptor(createTestEncryptionConfig(previousKeys: [base64_encode(random_bytes(32))]));

        $rotated->decrypt($stranger->encrypt('secret'));
    })->throws(DecryptionException::class, 'The encryption key is invalid or does not match');

    it('throws at construction when a previous key has the wrong length for the cipher', function (): void {
        new OpenSslEncryptor(createTestEncryptionConfig(previousKeys: [
            base64_encode(random_bytes(32)),
            base64_encode(random_bytes(16)),
        ]));
    })->throws(EncryptionException::class, 'Invalid previous encryption key at index 1');

    it('throws at construction when a previous key is not valid base64', function (): void {
        new OpenSslEncryptor(createTestEncryptionConfig(previousKeys: ['not base64!!']));
    })->throws(EncryptionException::class, 'Invalid previous encryption key at index 0');
});
