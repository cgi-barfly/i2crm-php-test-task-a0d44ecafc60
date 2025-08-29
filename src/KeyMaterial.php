<?php

namespace I2CRM\WSC;

/**
 * Holds derived keys for encryption and authentication.
 */
final class KeyMaterial
{
	/** @var string 16-byte IV */
	public string $iv;        // 16
	/** @var string 32-byte AES key */
	public string $cipherKey; // 32
	/** @var string 32-byte HMAC key */
	public string $macKey;    // 32
	/** @var string 32-byte reference key (unused) */
	public string $refKey;    // 32

	/**
	 * @param string $iv 16 bytes
	 * @param string $cipherKey 32 bytes
	 * @param string $macKey 32 bytes
	 * @param string $refKey 32 bytes
	 */
	public function __construct(string $iv, string $cipherKey, string $macKey, string $refKey)
	{
		$this->iv = $iv;
		$this->cipherKey = $cipherKey;
		$this->macKey = $macKey;
		$this->refKey = $refKey;
	}

	/**
	 * Derive key material from a 32-byte mediaKey and media type.
	 *
	 * @param string $mediaKey 32-byte key
	 * @param string $mediaType One of MediaType::*
	 * @return self
	 */
	public static function deriveFromMediaKey(string $mediaKey, string $mediaType): self
	{
		$expanded = Hkdf::expand($mediaKey, MediaType::applicationInfo($mediaType));
		$iv = substr($expanded, 0, 16);
		$cipherKey = substr($expanded, 16, 32);
		$macKey = substr($expanded, 48, 32);
		$refKey = substr($expanded, 80, 32);
		return new self($iv, $cipherKey, $macKey, $refKey);
	}
}


