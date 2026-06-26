<?php
/*
 * Archivo: app/core/Controller.php
 * Autor:   C3r0d4y
 *
 * Clase base de todos los controladores.
 * Provee métodos para renderizar vistas y enviar respuestas JSON.
 */

declare(strict_types=1);

class Controller
{
    // Renderiza una vista envuelta en el layout header/footer
    public function view(string $view, array $data = []): void
    {
        extract($data, EXTR_SKIP);

        require APP_ROOT . '/app/views/layouts/header.php';
        require APP_ROOT . "/app/views/{$view}.php";
        require APP_ROOT . '/app/views/layouts/footer.php';
    }

    // Envía una respuesta JSON y termina la ejecución
    protected function json(mixed $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($data);
        exit;
    }

    // Atajo para respuestas de error JSON
    protected function jsonError(int $code, string $msg): void
    {
        $this->json(['ok' => false, 'error' => $msg], $code);
    }
}
