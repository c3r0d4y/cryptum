<?php
/*
 * Archivo: app/models/Vault.php
 * Autor:   C3r0d4y
 *
 * Gestiona el almacenamiento temporal de blobs cifrados.
 * El servidor nunca recibe contraseñas ni archivos en claro:
 * solo guarda el blob ya cifrado por el cliente (Web Crypto API).
 *
 * Ciclo de vida de un vault:
 *   1. Cliente cifra el archivo en el navegador.
 *   2. Sube el blob cifrado → se asigna un token de 128 bits.
 *   3. El token genera un enlace de descarga única.
 *   4. Al primer GET del enlace el blob se sirve y se elimina.
 *   5. Cualquier vault que supere EXPIRY_SEC también se elimina.
 */

declare(strict_types=1);

final class Vault
{
    // ── Subida ────────────────────────────────────────────────────────────────

    public function store(string $rawBody): array
    {
        $this->cleanup();

        $activos = count(glob(VAULT_PATH . '*.enc') ?: []);
        if ($activos >= MAX_VAULTS) {
            throw new \OverflowException('Capacidad temporal agotada. Intenta en unos minutos.');
        }

        $body = json_decode($rawBody ?: '{}', true);
        if (!is_array($body) || empty($body['data'])) {
            throw new \InvalidArgumentException('Cuerpo de solicitud inválido.');
        }

        $blob = base64_decode($body['data'], true);
        if ($blob === false || strlen($blob) < 50) {
            throw new \InvalidArgumentException('Datos de archivo inválidos o corruptos.');
        }

        $maxBytes = MAX_FILE_MB * 1024 * 1024;
        if (strlen($blob) > $maxBytes) {
            throw new \LengthException('Archivo demasiado grande (máximo ' . MAX_FILE_MB . ' MB).');
        }

        // Verificar firma binaria del formato Cryptum
        if (substr($blob, 0, 4) !== 'C3VL') {
            throw new \UnexpectedValueException('El archivo no tiene formato Cryptum válido.');
        }

        if (!is_dir(VAULT_PATH)) {
            mkdir(VAULT_PATH, 0750, true);
        }

        $token = bin2hex(random_bytes(16));

        if (file_put_contents(VAULT_PATH . $token . '.enc', $blob) === false) {
            throw new \RuntimeException('Error al almacenar el archivo en bóveda.');
        }
        chmod(VAULT_PATH . $token . '.enc', 0600);

        $meta = [
            'created'    => time(),
            'downloaded' => false,
            'size'       => strlen($blob),
            // Hash parcial de IP para auditoría mínima sin almacenar dato personal
            'origin'     => substr(hash('sha256', $_SERVER['REMOTE_ADDR'] ?? ''), 0, 8),
        ];
        file_put_contents(VAULT_PATH . $token . '.meta', json_encode($meta));
        chmod(VAULT_PATH . $token . '.meta', 0600);

        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $url    = $scheme . '://' . $host . BASE_URL . '/?d=' . $token;

        return [
            'ok'         => true,
            'token'      => $token,
            'url'        => $url,
            'expires_at' => time() + EXPIRY_SEC,
            'expiry_sec' => EXPIRY_SEC,
            'size'       => strlen($blob),
        ];
    }

    // ── Descarga (única) ──────────────────────────────────────────────────────

    public function serve(string $token): void
    {
        $this->validateToken($token);

        $encFile  = VAULT_PATH . $token . '.enc';
        $metaFile = VAULT_PATH . $token . '.meta';

        if (!file_exists($encFile) || !file_exists($metaFile)) {
            throw new \RuntimeException('Enlace inválido, ya utilizado o expirado.', 404);
        }

        $meta = json_decode((string) file_get_contents($metaFile), true);
        if (!is_array($meta)) {
            $this->delete($token);
            throw new \RuntimeException('Metadatos corruptos.', 500);
        }

        if ((time() - ($meta['created'] ?? 0)) > EXPIRY_SEC) {
            $this->delete($token);
            throw new \RuntimeException('El enlace ha expirado (límite: 5 minutos).', 410);
        }

        if (!empty($meta['downloaded'])) {
            $this->delete($token);
            throw new \RuntimeException('Este enlace ya fue utilizado. Solo permite una descarga.', 410);
        }

        // Marcar como descargado ANTES de servir para evitar race conditions
        $meta['downloaded']    = true;
        $meta['downloaded_at'] = time();
        file_put_contents($metaFile, json_encode($meta));

        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . filesize($encFile));
        header('Content-Disposition: attachment; filename="vault.c3v"');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('X-Cryptum-Token: consumed');

        readfile($encFile);
        $this->delete($token);

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }
        exit;
    }

    // ── Estado del vault ──────────────────────────────────────────────────────

    public function status(string $token): array
    {
        $this->validateToken($token);

        $metaFile = VAULT_PATH . $token . '.meta';
        if (!file_exists($metaFile)) {
            return ['valid' => false, 'reason' => 'not_found'];
        }

        $meta      = json_decode((string) file_get_contents($metaFile), true);
        $elapsed   = time() - ($meta['created'] ?? 0);
        $remaining = EXPIRY_SEC - $elapsed;

        if ($remaining <= 0) {
            $this->delete($token);
            return ['valid' => false, 'reason' => 'expired'];
        }

        if (!empty($meta['downloaded'])) {
            $this->delete($token);
            return ['valid' => false, 'reason' => 'used'];
        }

        return [
            'valid'     => true,
            'remaining' => $remaining,
            'size'      => $meta['size'] ?? 0,
        ];
    }

    // ── Dispositivos USB ──────────────────────────────────────────────────────

    public function listUsb(): array
    {
        $raw = shell_exec('lsblk -J -o NAME,TRAN,SIZE,LABEL,MOUNTPOINT,TYPE,VENDOR,MODEL,FSTYPE,RM,HOTPLUG 2>/dev/null');

        if (!$raw) {
            return ['ok' => true, 'devices' => [], 'extra_mounts' => [], 'note' => 'lsblk no disponible en este sistema'];
        }

        $data    = json_decode($raw, true);
        $devices = [];

        foreach ($data['blockdevices'] ?? [] as $dev) {
            $isUSB = ($dev['tran'] === 'usb');
            $isRM  = ($dev['rm']      === true || $dev['rm']      === '1');
            $isHot = ($dev['hotplug'] === true || $dev['hotplug'] === '1');

            if (!$isUSB && !$isRM && !$isHot) continue;
            if ($dev['type'] !== 'disk') continue;

            $vendor = trim((string) ($dev['vendor'] ?? ''));
            $model  = trim((string) ($dev['model']  ?? ''));

            $entry = [
                'name'   => $dev['name'],
                'path'   => '/dev/' . $dev['name'],
                'size'   => $dev['size'] ?? '?',
                'vendor' => $vendor,
                'model'  => $model ?: ($vendor ?: 'Dispositivo removible'),
                'tran'   => $dev['tran'] ?? 'removible',
                'parts'  => [],
            ];

            foreach ($dev['children'] ?? [] as $part) {
                $mp = trim((string) ($part['mountpoint'] ?? ''));
                $entry['parts'][] = [
                    'name'       => $part['name'],
                    'path'       => '/dev/' . $part['name'],
                    'size'       => $part['size'] ?? '?',
                    'label'      => trim((string) ($part['label']  ?? '')),
                    'fstype'     => trim((string) ($part['fstype'] ?? '')),
                    'mountpoint' => $mp,
                    'mounted'    => $mp !== '',
                ];
            }

            $devices[] = $entry;
        }

        // Puntos de montaje adicionales en /media, /mnt, /run/media
        $extraMounts = [];
        $mntRaw      = shell_exec('cat /proc/mounts 2>/dev/null') ?? '';
        foreach (explode("\n", $mntRaw) as $line) {
            $parts = explode(' ', trim($line));
            if (count($parts) < 2) continue;
            $mp = $parts[1];
            if (!str_starts_with($mp, '/media/') && !str_starts_with($mp, '/run/media/') && !str_starts_with($mp, '/mnt/')) continue;
            $alreadyIn = false;
            foreach ($devices as $d) {
                foreach ($d['parts'] as $p) {
                    if ($p['mountpoint'] === $mp) { $alreadyIn = true; break 2; }
                }
            }
            if (!$alreadyIn) {
                $extraMounts[] = ['device' => $parts[0], 'mountpoint' => $mp, 'fstype' => $parts[2] ?? ''];
            }
        }

        return ['ok' => true, 'devices' => $devices, 'extra_mounts' => $extraMounts];
    }

    // ── Privados ──────────────────────────────────────────────────────────────

    // Elimina vault: sobrescribe con ceros antes de borrar
    public function delete(string $token): void
    {
        $encFile = VAULT_PATH . $token . '.enc';
        if (file_exists($encFile)) {
            $size = filesize($encFile);
            file_put_contents($encFile, str_repeat("\0", min($size ?: 0, 4096)));
            @unlink($encFile);
        }
        @unlink(VAULT_PATH . $token . '.meta');
    }

    // Limpia vaults expirados o ya descargados
    private function cleanup(): void
    {
        foreach (glob(VAULT_PATH . '*.meta') ?: [] as $metaFile) {
            $meta  = json_decode((string) file_get_contents($metaFile), true) ?: [];
            $token = basename($metaFile, '.meta');
            $age   = time() - ($meta['created'] ?? 0);
            if ($age > EXPIRY_SEC || !empty($meta['downloaded'])) {
                $this->delete($token);
            }
        }
    }

    private function validateToken(string $token): void
    {
        if (!preg_match('/^[0-9a-f]{32}$/', $token)) {
            throw new \InvalidArgumentException('Token inválido.', 400);
        }
    }
}
