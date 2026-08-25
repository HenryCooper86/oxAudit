<?php
function restore(array $request) {
    // json_decode builds plain data and never instantiates a class, so a
    // crafted payload cannot reach a magic method.
    return json_decode($request['state'], true);
}
