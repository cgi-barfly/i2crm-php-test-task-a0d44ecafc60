<?php

namespace I2CRM\WSC;

final class Crypto
{
	public static function pkcs7Pad(string $data, int $blockSize = 16): string
	{
		$padLen = $blockSize - (strlen($data) % $blockSize);
		return $data . str_repeat(chr($padLen), $padLen);
	}

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

	public static function aesCbcEncrypt(string $plaintext, string $key, string $iv): string
	{
		$input = self::pkcs7Pad($plaintext);
		return openssl_encrypt($input, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
	}

	public static function aesCbcDecrypt(string $ciphertext, string $key, string $iv): string
	{
		$decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
		return self::pkcs7Unpad($decrypted);
	}

	public static function mac10(string $data, string $macKey): string
	{
		return substr(hash_hmac('sha256', $data, $macKey, true), 0, 10);
	}
}


