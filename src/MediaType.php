<?php

namespace I2CRM\WSC;

/**
 * Media types supported for WhatsApp-style media key derivation.
 */
final class MediaType
{
	public const IMAGE = 'IMAGE';
	public const VIDEO = 'VIDEO';
	public const AUDIO = 'AUDIO';
	public const DOCUMENT = 'DOCUMENT';

	/**
	 * Get HKDF application info string used for a specific media type.
	 *
	 * @param string $mediaType One of self::IMAGE|VIDEO|AUDIO|DOCUMENT
	 * @return string The context string to use in HKDF expand step
	 * @throws \InvalidArgumentException If media type is unknown
	 */
	public static function applicationInfo(string $mediaType): string
	{
		switch ($mediaType) {
			case self::IMAGE:
				return 'WhatsApp Image Keys';
			case self::VIDEO:
				return 'WhatsApp Video Keys';
			case self::AUDIO:
				return 'WhatsApp Audio Keys';
			case self::DOCUMENT:
				return 'WhatsApp Document Keys';
			default:
				throw new \InvalidArgumentException('Unknown media type: ' . $mediaType);
		}
	}
}


