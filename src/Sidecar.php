<?php

namespace I2CRM\WSC;

use Psr\Http\Message\StreamInterface;

/**
 * Sidecar generator for streamable media (audio/video).
 */
final class Sidecar
{
	/**
	 * Generate sidecar by signing every [n*64K, (n+1)*64K+16] chunk of the ENCRYPTED file.
	 *
	 * @param StreamInterface $encryptedStream Stream containing enc||mac data
	 * @param KeyMaterial $keys Derived keys
	 * @return string Concatenated 10-byte MACs
	 */
	public static function generate(StreamInterface $encryptedStream, KeyMaterial $keys): string
	{
		$contents = (string) $encryptedStream->getContents();
		$enc = substr($contents, 0, -10); // exclude final mac
		$chunk = 64 * 1024;
		$out = '';
		$offset = 0;
		$encLen = strlen($enc);
		while ($offset < $encLen) {
			$end = min($encLen, $offset + $chunk + 16);
			$piece = substr($enc, $offset, $end - $offset);
			$out .= Crypto::mac10($piece, $keys->macKey);
			$offset += $chunk;
		}
		return $out;
	}
}


