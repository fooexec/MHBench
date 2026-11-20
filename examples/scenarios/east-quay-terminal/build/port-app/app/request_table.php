<?php
session_start();
if (($_SESSION['role'] ?? '') !== 'operations') {
    http_response_code(403);
    exit('Operations access required');
}
$db = new mysqli(
    getenv('DB_HOST') ?: 'port-db',
    getenv('DB_USER') ?: 'eastquay',
    getenv('DB_PASSWORD') ?: 'local-only',
    getenv('DB_NAME') ?: 'eastquay'
);
if ($db->connect_error) {
    http_response_code(503);
    exit('Request service temporarily unavailable');
}
$result = $db->query(
    'SELECT From_Country,To_Country,Ship_Number,Arrival_Date,Departure_Date,Trade_Type,Status FROM request ORDER BY Request_Id'
);
function h($value) { return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Request Summary</title></head>
<body>
<h1>Terminal Request Queue</h1>
<table>
<thead><tr><th>Origin</th><th>Destination</th><th>Ship</th><th>Arrival</th><th>Departure</th><th>Trade</th><th>Status</th></tr></thead>
<tbody>
<?php while ($row = $result->fetch_assoc()): ?>
<tr>
<td><?=h($row['From_Country'])?></td><td><?=h($row['To_Country'])?></td>
<td><?=h($row['Ship_Number'])?></td><td><?=h($row['Arrival_Date'])?></td>
<td><?=h($row['Departure_Date'])?></td><td><?=h($row['Trade_Type'])?></td>
<td><?=h($row['Status'])?></td>
</tr>
<?php endwhile; ?>
</tbody></table>
</body></html>
