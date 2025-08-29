<?php

namespace I2CRM\WSC;

/**
 * Low-level cryptographic helpers (padding, AES-CBC, truncated HMAC).
 */
final class Crypto
{
	/**
	 * Apply PKCS#7 padding.
	 *
	 * @param string $data
	 * @param int $blockSize
	 * @return string
	 */
	public static function pkcs7Pad(string $data, int $blockSize = 16): string
	{
		$padLen = $blockSize - (strlen($data) % $blockSize);
		return $data . str_repeat(chr($padLen), $padLen);
	}

	/**
	 * Remove PKCS#7 padding and validate.
	 *
	 * @param string $data
	 * @param int $blockSize
	 * @return string
	 */
	public static function pkcs7Unpad(string $data, int $blockSize = 16): string
	{
		$len = strlen($data);
		if ($len === 0 || $len % $blockSize !== 0) {
			throw new \RuntimeException('Invalid padded data length');
		}
		$padLen = ord($data[$len - 1]);
		if ($padLen < 1 || $padLen > $blockSize) {
			throw new \RuntimeException('Invalid padding');
		}
		for ($i = 1; $i <= $padLen; $i++) {
			if (ord($data[$len - $i]) !== $padLen) {
				throw new \RuntimeException('Invalid padding');
			}
		}
		return substr($data, 0, $len - $padLen);
	}

	/**
	 * AES-256-CBC with manual PKCS#7 padding.
	 *
	 * @param string $plaintext
	 * @param string $key 32 bytes
	 * @param string $iv 16 bytes
	 * @return string ciphertext
	 */
	public static function aesCbcEncrypt(string $plaintext, string $key, string $iv): string|false
	{
		$input = self::pkcs7Pad($plaintext);
		return openssl_encrypt($input, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
	}

	/**
	 * AES-256-CBC with manual PKCS#7 unpadding.
	 *
	 * @param string $ciphertext
	 * @param string $key 32 bytes
	 * @param string $iv 16 bytes
	 * @return string plaintext
	 */
	public static function aesCbcDecrypt(string $ciphertext, string $key, string $iv): string
	{
		$decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
		if($decrypted)
		{
			return self::pkcs7Unpad($decrypted);
		}
		else
		{
			throw new \RuntimeException('Failed to decrypt ciphertext');
		}
	}


	/**
	 * Truncated HMAC-SHA256 (first 10 bytes), per WhatsApp spec.
	 *
	 * @param string $data
	 * @param string $macKey 32-byte key
	 * @return string 10-byte MAC
	 */
	public static function mac10(string $data, string $macKey): string
	{
		return substr(hash_hmac('sha256', $data, $macKey, true), 0, 10);
	}
}


