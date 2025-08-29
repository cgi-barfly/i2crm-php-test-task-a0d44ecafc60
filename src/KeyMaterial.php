<?php

namespace I2CRM\WSC;

final class KeyMaterial
{
	public string $iv;        // 16
	public string $cipherKey; // 32
	public string $macKey;    // 32
	public string $refKey;    // 32

	public function __construct(string $iv, string $cipherKey, string $macKey, string $refKey)
	{
		$this->iv = $iv;
		$this->cipherKey = $cipherKey;
		$this->macKey = $macKey;
		$this->refKey = $refKey;
	}

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


