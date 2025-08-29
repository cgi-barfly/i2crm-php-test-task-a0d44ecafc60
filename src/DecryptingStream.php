<?php

namespace I2CRM\WSC;

use Psr\Http\Message\StreamInterface;

/**
 * Stream decorator that validates MAC and decrypts the underlying encrypted stream.
 * Expects format: enc || mac10( iv || enc ).
 */
final class DecryptingStream implements StreamInterface
{
	private StreamInterface $source;
	private KeyMaterial $keys;
	private string $buffer = '';
	private bool $fullyRead = false;
	private ?int $size = null;

	/**
	 * @param StreamInterface $source encrypted source stream (enc||mac)
	 * @param KeyMaterial $keys derived keys used for validation and decryption
	 */
	public function __construct(StreamInterface $source, KeyMaterial $keys)
	{
		$this->source = $source;
		$this->keys = $keys;
	}

	/**
	 * Helper to build from mediaKey and mediaType.
	 *
	 * @param StreamInterface $source
	 * @param string $mediaKey 32-byte key
	 * @param string $mediaType One of MediaType::*
	 * @return self
	 */
	public static function from(StreamInterface $source, string $mediaKey, string $mediaType): self
	{
		return new self($source, KeyMaterial::deriveFromMediaKey($mediaKey, $mediaType));
	}

	/** Ensure decryption is performed once after MAC verification. */
	private function ensureDecrypted(): void
	{
		if ($this->fullyRead) {
			return;
		}
		$encrypted = (string) $this->source->getContents();
		if (strlen($encrypted) < 10) {
			throw new \RuntimeException('Encrypted data too short');
		}
		$file = substr($encrypted, 0, -10);
		$mac = substr($encrypted, -10);
		$calcMac = Crypto::mac10($this->keys->iv . $file, $this->keys->macKey);
		if (!hash_equals($mac, $calcMac)) {
			throw new \RuntimeException('MAC verification failed');
		}
		$plaintext = Crypto::aesCbcDecrypt($file, $this->keys->cipherKey, $this->keys->iv);
		$this->buffer = $plaintext;
		$this->size = strlen($this->buffer);
		$this->fullyRead = true;
	}

	/** @inheritDoc */
	public function __toString(): string
	{
		try {
			$this->ensureDecrypted();
			return $this->buffer;
		} catch (\Throwable $e) {
			return '';
		}
	}

	/** @inheritDoc */
	public function close(): void
	{
		$this->source->close();
		$this->buffer = '';
	}

	/** @inheritDoc */
	public function detach()
	{
		return $this->source->detach();
	}

	/** @inheritDoc */
	public function getSize(): ?int
	{
		$this->ensureDecrypted();
		return $this->size;
	}

	/** @inheritDoc */
	public function tell(): int
	{
		throw new \RuntimeException('Not seekable');
	}

	/** @inheritDoc */
	public function eof(): bool
	{
		$this->ensureDecrypted();
		return $this->buffer === '';
	}

	/** @inheritDoc */
	public function isSeekable(): bool
	{
		return false;
	}

	/** @inheritDoc */
	public function seek($offset, $whence = SEEK_SET): void
	{
		throw new \RuntimeException('Not seekable');
	}

	/** @inheritDoc */
	public function rewind(): void
	{
		throw new \RuntimeException('Not seekable');
	}

	/** @inheritDoc */
	public function isWritable(): bool
	{
		return false;
	}

	/** @inheritDoc */
	public function write($string): int
	{
		throw new \RuntimeException('Not writable');
	}

	/** @inheritDoc */
	public function isReadable(): bool
	{
		return true;
	}

	/** @inheritDoc */
	public function read($length): string
	{
		$this->ensureDecrypted();
		$chunk = substr($this->buffer, 0, $length);
		$this->buffer = substr($this->buffer, strlen($chunk));
		return $chunk;
	}

	/** @inheritDoc */
	public function getContents(): string
	{
		$this->ensureDecrypted();
		$all = $this->buffer;
		$this->buffer = '';
		return $all;
	}

	/** @inheritDoc */
	public function getMetadata($key = null)
	{
		return $key === null ? [] : null;
	}
}


