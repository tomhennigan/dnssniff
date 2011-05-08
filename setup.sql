SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

CREATE TABLE IF NOT EXISTS `dns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(512) CHARACTER SET ascii NOT NULL,
  `src_host` varchar(512) COLLATE utf8_unicode_ci NOT NULL,
  `dst_ip` varchar(512) CHARACTER SET ascii NOT NULL,
  `dst_host` varchar(512) COLLATE utf8_unicode_ci NOT NULL,
  `domain` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `when` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `domain` (`domain`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

