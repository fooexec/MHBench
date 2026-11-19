-- Nacos 2.5.5 adds encrypted-data and gray-release columns to the Nacos 2.0
-- schema shipped with Open WES. Keep the upstream configuration rows while
-- supplying the columns expected by the pinned Nacos server. Table definitions
-- are adapted from nacos/nacos-server 2.5.5 (Apache-2.0).
USE `nacos_config`;

ALTER TABLE `config_info`
    ADD COLUMN `encrypted_data_key` varchar(1024) NOT NULL DEFAULT '' COMMENT 'encrypted_data_key';

ALTER TABLE `his_config_info`
    ADD COLUMN `encrypted_data_key` varchar(1024) NOT NULL DEFAULT '' COMMENT 'encrypted_data_key',
    ADD COLUMN `publish_type` varchar(50) DEFAULT 'formal' COMMENT 'publish type gray or formal',
    ADD COLUMN `gray_name` varchar(50) DEFAULT NULL COMMENT 'gray name',
    ADD COLUMN `ext_info` longtext DEFAULT NULL COMMENT 'ext info';

CREATE TABLE IF NOT EXISTS `config_info_gray` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'id',
    `data_id` varchar(255) NOT NULL COMMENT 'data_id',
    `group_id` varchar(128) NOT NULL COMMENT 'group_id',
    `content` longtext NOT NULL COMMENT 'content',
    `md5` varchar(32) DEFAULT NULL COMMENT 'md5',
    `src_user` text COMMENT 'src_user',
    `src_ip` varchar(100) DEFAULT NULL COMMENT 'src_ip',
    `gmt_create` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'gmt_create',
    `gmt_modified` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'gmt_modified',
    `app_name` varchar(128) DEFAULT NULL COMMENT 'app_name',
    `tenant_id` varchar(128) DEFAULT '' COMMENT 'tenant_id',
    `gray_name` varchar(128) NOT NULL COMMENT 'gray_name',
    `gray_rule` text NOT NULL COMMENT 'gray_rule',
    `encrypted_data_key` varchar(256) NOT NULL DEFAULT '' COMMENT 'encrypted_data_key',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_configinfogray_datagrouptenantgray`
        (`data_id`, `group_id`, `tenant_id`, `gray_name`),
    KEY `idx_dataid_gmt_modified` (`data_id`, `gmt_modified`),
    KEY `idx_gmt_modified` (`gmt_modified`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='config_info_gray';
