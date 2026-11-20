CREATE DATABASE IF NOT EXISTS nacos_config CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS openwes CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'nacos_range'@'%' IDENTIFIED BY 'nacos-range-local';
GRANT ALL PRIVILEGES ON nacos_config.* TO 'nacos_range'@'%';

CREATE USER IF NOT EXISTS 'openwes_range'@'%' IDENTIFIED BY 'openwes-range-local';
GRANT ALL PRIVILEGES ON openwes.* TO 'openwes_range'@'%';
