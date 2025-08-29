<?php

namespace I2CRM\WSC;

use Psr\Http\Message\StreamInterface;
use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\Psr7\Stream;

/**
 * Stream decorator that encrypts the entire underlying stream content on read.
 * Result format: enc || mac10( iv || enc ).
 */
final class EncryptingStream implements StreamInterface
{
	private StreamInterface $source;
	private KeyMaterial $keys;
	private string $buffer = '';
	private bool $fullyRead = false;
	private ?int $size = null;

	/**
	 * @param StreamInterface $source plaintext source stream
	 * @param KeyMaterial $keys derived keys
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

	/** Ensure encryption is performed once and cached. */
	private function ensureEncrypted(): void
	{
		if ($this->fullyRead) {
			return;
		}
		$plaintext = (string) $this->source->getContents();
		$enc = Crypto::aesCbcEncrypt($plaintext, $this->keys->cipherKey, $this->keys->iv);
		$mac = Crypto::mac10($this->keys->iv . $enc, $this->keys->macKey);
		$this->buffer = $enc . $mac;
		$this->size = strlen($this->buffer);
		$this->fullyRead = true;
	}

	/** @inheritDoc */
	public function __toString(): string
	{
		try {
			$this->ensureEncrypted();
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
		$this->ensureEncrypted();
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
		$this->ensureEncrypted();
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
		$this->ensureEncrypted();
		$chunk = substr($this->buffer, 0, $length);
		$this->buffer = substr($this->buffer, strlen($chunk));
		return $chunk;
	}

	/** @inheritDoc */
	public function getContents(): string
	{
		$this->ensureEncrypted();
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


