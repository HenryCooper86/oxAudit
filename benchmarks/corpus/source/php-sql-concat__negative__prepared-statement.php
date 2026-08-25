<?php
function findUser(PDO $db, array $request) {
    // The id never reaches the SQL text; the driver binds it separately.
    $statement = $db->prepare("SELECT * FROM users WHERE id = ?");
    $statement->execute([$request['id']]);
    return $statement->fetch();
}
