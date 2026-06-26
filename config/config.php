<?php
/*
 * Archivo: config/config.php
 * Autor:   C3r0d4y
 *
 * Constantes globales de la aplicación.
 */

declare(strict_types=1);

if (!defined('APP_NAME')) {
    define('APP_NAME',    'Cryptum');
    // Para producción en raíz del dominio usar APP_BASE_URL="" en el entorno.
    // Se usa !== false para distinguir entre "no definida" (false) y "definida vacía" ("").
    $envBase = getenv('APP_BASE_URL');
    define('BASE_URL', rtrim($envBase !== false ? (string)$envBase : '/cryptum', '/'));
    define('APP_ROOT',    dirname(__DIR__));
    define('VAULT_PATH',  APP_ROOT . '/storage/vault/');
    define('MAX_FILE_MB', 100);
    define('EXPIRY_SEC',  300);
    define('MAX_VAULTS',  500);
}
