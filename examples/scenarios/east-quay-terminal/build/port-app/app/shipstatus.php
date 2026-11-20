<?php
session_start();
if (($_SESSION['role'] ?? '') !== 'operations') {
    http_response_code(403);
    exit('Operations access required');
}
http_response_code(409);
exit('Use the clearance and yard-dispatch workflow for shipment status changes');
