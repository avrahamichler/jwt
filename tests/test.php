
<?php


use jwt\Config;
use jwt\TokenBuilder;
use jwt\TokenVerifier;

require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload



$a = new Config();
$b = new TokenBuilder($a);
$c = new TokenVerifier($a);

var_dump($c);