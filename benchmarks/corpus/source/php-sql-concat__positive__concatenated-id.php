<?php
function findUser(PDO $db, array $request) {
    $sql = "SELECT * FROM users WHERE id = " . $request['id'];
    return $db->query($sql);
}
