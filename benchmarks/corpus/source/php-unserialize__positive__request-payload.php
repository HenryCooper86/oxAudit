<?php
function restore(array $request) {
    return unserialize($request['state']);
}
