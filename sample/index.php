<?php
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
error_reporting(-1);

require '../vendor/autoload.php';
use codecun\authbon\Auth;

abstract class index
{
    public static function Open() 
    {
        $itinerario = new Itinerario();
        $_SESSION['head'] = $itinerario->open();
    }

}


echo "<pre>";
Index::Open();
