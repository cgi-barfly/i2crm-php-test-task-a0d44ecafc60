<?php

namespace I2CRM\WSC;

/**
 * HKDF-SHA256 helper to derive WhatsApp media key material.
 */
final class Hkdf
{
	/**
	 * Expand a 32-byte media key into 112 bytes using HKDF-SHA256.
	 *
	 * @param string $mediaKey 32-byte random key
	 * @param string $applicationInfo context-specific info string
	 * @return string 112-byte expanded key
	 */
	public static function expand(string $mediaKey, string $applicationInfo): string
	{
		if (strlen($mediaKey) !== 32) {
			throw new \InvalidArgumentException('mediaKey must be 32 bytes');
		}
		// HKDF-Extract with empty salt
		$prk = hash_hmac('sha256', $mediaKey, str_repeat("\x00", 32), true);
		// HKDF-Expand to 112 bytes
		$length = 112;
		$output = '';
		$block = '';
		$counter = 1;
		while (strlen($output) < $length) {
			$block = hash_hmac('sha256', $block . $applicationInfo . chr($counter), $prk, true);
			$output .= $block;
			$counter++;
		}
		return substr($output, 0, $length);
	}
}


