<?php

namespace I2CRM\WSC;

use Psr\Http\Message\StreamInterface;

final class DecryptingStream implements StreamInterface
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

	public function __toString(): string
	{
		try {
			$this->ensureDecrypted();
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
		$this->ensureDecrypted();
		return $this->size;
	}

	public function tell(): int
	{
		throw new \RuntimeException('Not seekable');
	}

	public function eof(): bool
	{
		$this->ensureDecrypted();
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
		$this->ensureDecrypted();
		$chunk = substr($this->buffer, 0, $length);
		$this->buffer = substr($this->buffer, strlen($chunk));
		return $chunk;
	}

	public function getContents(): string
	{
		$this->ensureDecrypted();
		$all = $this->buffer;
		$this->buffer = '';
		return $all;
	}

	public function getMetadata($key = null)
	{
		return $key === null ? [] : null;
	}
}


