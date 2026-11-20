<?php
session_start();
if (($_SESSION['role'] ?? '') !== 'carrier') {
    http_response_code(403);
    exit('Carrier access required');
}
$db = new mysqli(
    getenv('DB_HOST') ?: 'port-db',
    getenv('DB_USER') ?: 'eastquay',
    getenv('DB_PASSWORD') ?: 'local-only',
    getenv('DB_NAME') ?: 'eastquay'
);
if ($db->connect_error) {
    http_response_code(503);
    exit('Status service temporarily unavailable');
}
$country = (string)($_SESSION['country'] ?? '');
$shipNumber = filter_var($_POST['shipnumber'] ?? null, FILTER_VALIDATE_INT);
if ($shipNumber === false || $shipNumber === null) {
    http_response_code(400);
    exit('Invalid ship number');
}
$countryQuery = $db->prepare('SELECT Id FROM country WHERE Name=?');
$countryQuery->bind_param('s', $country);
$countryQuery->execute();
$countryRow = $countryQuery->get_result()->fetch_assoc();
if (!$countryRow) {
    http_response_code(404);
    exit('Country not found');
}
$countryId = (int)$countryRow['Id'];
$shipQuery = $db->prepare('SELECT Curr_Status,Name FROM ships WHERE Id=? AND Number=?');
$shipQuery->bind_param('ii', $countryId, $shipNumber);
$shipQuery->execute();
$ship = $shipQuery->get_result()->fetch_assoc();
if (!$ship) {
    http_response_code(404);
    exit('Ship not found');
}
$labels = [
    'AL' => 'Arrived Loaded',
    'AU' => 'Arrived Unloaded',
    'DL' => 'Departed Loaded',
    'DU' => 'Departed Unloaded',
    'PL' => 'Present Loaded',
    'PU' => 'Present Unloaded',
    'Done' => 'Done',
];
$status = $labels[$ship['Curr_Status']] ?? 'Unknown';
echo 'The ship ' . htmlspecialchars($ship['Name'], ENT_QUOTES, 'UTF-8')
    . ' current status is - ' . htmlspecialchars($status, ENT_QUOTES, 'UTF-8');
