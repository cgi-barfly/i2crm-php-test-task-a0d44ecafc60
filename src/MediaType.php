<?php

namespace I2CRM\WSC;

final class MediaType
{
	public const IMAGE = 'IMAGE';
	public const VIDEO = 'VIDEO';
	public const AUDIO = 'AUDIO';
	public const DOCUMENT = 'DOCUMENT';

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


