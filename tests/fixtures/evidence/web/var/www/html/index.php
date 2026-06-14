<?php
require_once 'includes/config.php';
require_once 'includes/db.php';
$page = $_GET['p'] ?? 'home';
include "pages/$page.php";
?>
