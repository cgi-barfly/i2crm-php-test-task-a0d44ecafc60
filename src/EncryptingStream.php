<?php

namespace I2CRM\WSC;

use Psr\Http\Message\StreamInterface;
use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\Psr7\Stream;

final class EncryptingStream implements StreamInterface
{
	private StreamInterface $source;
	private KeyMaterial $keys;
	private string $buffer = '';
	private bool $fullyRead = false;
	private ?int $size = null;

	public function __construct(StreamInterface $source, KeyMaterial $keys)
	{
		$this->source = $source;
		$this->keys = $keys;
	}

	public static function from(StreamInterface $source, string $mediaKey, string $mediaType): self
	{
		return new self($source, KeyMaterial::deriveFromMediaKey($mediaKey, $mediaType));
	}

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

	public function __toString(): string
	{
		try {
			$this->ensureEncrypted();
			return $this->buffer;
		} catch (\Throwable $e) {
			return '';
		}
	}

	public function close(): void
	{
		$this->source->close();
		$this->buffer = '';
	}

	public function detach()
	{
		return $this->source->detach();
	}

	public function getSize(): ?int
	{
		$this->ensureEncrypted();
		return $this->size;
	}

	public function tell(): int
	{
		throw new \RuntimeException('Not seekable');
	}

	public function eof(): bool
	{
		$this->ensureEncrypted();
		return $this->buffer === '';
	}

	public function isSeekable(): bool
	{
		return false;
	}

	public function seek($offset, $whence = SEEK_SET): void
	{
		throw new \RuntimeException('Not seekable');
	}

	public function rewind(): void
	{
		throw new \RuntimeException('Not seekable');
	}

	public function isWritable(): bool
	{
		return false;
	}

	public function write($string): int
	{
		throw new \RuntimeException('Not writable');
	}

	public function isReadable(): bool
	{
		return true;
	}

	public function read($length): string
	{
		$this->ensureEncrypted();
		$chunk = substr($this->buffer, 0, $length);
		$this->buffer = substr($this->buffer, strlen($chunk));
		return $chunk;
	}

	public function getContents(): string
	{
		$this->ensureEncrypted();
		$all = $this->buffer;
		$this->buffer = '';
		return $all;
	}

	public function getMetadata($key = null)
	{
		return $key === null ? [] : null;
	}
}


