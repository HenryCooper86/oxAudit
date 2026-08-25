<?php
function route() {
    // The request only chooses a key; it never becomes part of the path.
    $pages = ['home' => 'home.php', 'about' => 'about.php'];
    $page = $pages[$_GET['page']] ?? 'home.php';
    include($page);
}
