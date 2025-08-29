### Testing the WhatsApp Stream Crypto package from the command line (Unix shell)

This guide shows how to verify encryption/decryption and sidecar generation using the provided `samples/` folder only. Keys are already present as `samples/<TYPE>.key`.

#### Prerequisites

- PHP 8.x available in PATH
- Composer installed
- This repository cloned/extracted

#### Install dependencies

- In the project root:
  - composer install -n

#### Keys

- Keys are provided in `samples/<TYPE>.key` (either 32 raw bytes or 64 hex). You do not need any other folder.

#### Quick round‑trip test (prove encrypt/decrypt pipeline)

Example with IMAGE:

1) Create output folder
- mkdir -p out

2) Generate a random mediaKey for testing (hex)
- KEY=$(php -r 'echo bin2hex(random_bytes(32));')

3) Encrypt the original sample
- php bin/encrypt IMAGE "$KEY" samples/IMAGE.original out/IMAGE.encrypted

4) Decrypt it back
- php bin/decrypt IMAGE "$KEY" out/IMAGE.encrypted out/IMAGE.decrypted

5) Compare hashes
- sha256sum samples/IMAGE.original
- sha256sum out/IMAGE.decrypted
- Hashes must match.

#### Decrypt provided encrypted samples using keys from `samples/*.key`

- Set KEY from `samples/<TYPE>.key`:
  - If the file contains 64‑char hex:
    - KEY=$(tr -d '\n\r' < samples/IMAGE.key)
  - If the file contains raw 32 bytes:
    - KEY=$(xxd -p -c 256 samples/IMAGE.key | tr -d '\n\r')

- Decrypt and compare (examples):
  - IMAGE:
    - php bin/decrypt IMAGE "$KEY" samples/IMAGE.encrypted out/IMAGE.decrypted
    - sha256sum samples/IMAGE.original
    - sha256sum out/IMAGE.decrypted
  - AUDIO:
    - php bin/decrypt AUDIO "$KEY" samples/AUDIO.encrypted out/AUDIO.decrypted
    - compare with samples/AUDIO.original
  - VIDEO:
    - php bin/decrypt VIDEO "$KEY" samples/VIDEO.encrypted out/VIDEO.decrypted
    - compare with samples/VIDEO.original

#### Sidecar verification (VIDEO/AUDIO)

If you want to also verify sidecar generation for streamable media (VIDEO):

- php bin/sidecar VIDEO "$KEY" samples/VIDEO.original out/VIDEO.sidecar
- Compare `samples/VIDEO.sidecar` with `out/VIDEO.sidecar`:
  - sha256sum samples/VIDEO.sidecar
  - sha256sum out/VIDEO.sidecar

#### Using the decorators programmatically

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use I2CRM\WSC\{KeyMaterial, EncryptingStream, DecryptingStream, MediaType};
use GuzzleHttp\Psr7\Utils;

$mediaKeyHex = getenv('KEY_HEX'); // 64 hex chars
$mediaKey = hex2bin($mediaKeyHex);
$keys = KeyMaterial::deriveFromMediaKey($mediaKey, MediaType::IMAGE);

// Encrypt
$plain = Utils::streamFor(file_get_contents('samples/IMAGE.original'));
$enc = new EncryptingStream($plain, $keys);
file_put_contents('out/IMAGE.enc', $enc->getContents());

// Decrypt
$encStream = Utils::streamFor(file_get_contents('out/IMAGE.enc'));
$dec = new DecryptingStream($encStream, $keys);
file_put_contents('out/IMAGE.dec', $dec->getContents());
```

#### Troubleshooting

- "MAC verification failed": mediaKey doesn’t match the encrypted sample or media type is wrong.
- "Invalid mediaKey length": ensure `.key` files are 32 bytes raw or 64 hex chars.
- Sidecar mismatch: only expected to match when you use the exact same mediaKey as used for `samples/<TYPE>.sidecar`.


