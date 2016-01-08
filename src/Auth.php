<?php
namespace codecun\authbon;
use codecun\authbon\PasswordHash as CPass;


/*==============================================================================================================================
 * @access public Class Auth with bonfire
 * @author Humberto Santos
 * @version 1.1.x-dev
 * Url Site: Jassan.mx
 * Url Site: codecun.com
==============================================================================================================================*/
class Auth
{
    // --- ATTRIBUTES ---
    private $_cpass            = null;

    /*==============================================================================================================================
    * Autentificacion con el Objeto Header
    ==============================================================================================================================*/
    public function login($user, $password, $model)
    {
        // Check whether the account has been banned.
        if ($model->banned) {
            return false;
        }

        // Check whether the username, email, or password doesn't exist.
        if ($model == false) {
            return false;
        }

        // Check whether the account has been soft deleted. The >= 1 check ensures
        // this will still work if the deleted field is a UNIX timestamp.
        if ($model->deleted >= 1) {
            return false;
        }

        // Try password
        if (! $this->check_password($password, $model->password_hash)) {
            return false;
        }

        // Check whether the user needs to reset their password.
        if ($model->force_password_reset == 1) {
            return false;
        }

        return true;
    }

    public function check_password($password, $hash)
    {
        // Load the password hash library
        $this->_cpass = new CPass(-1);

        // Try password
        return $this->_cpass->CheckPassword($password, $hash);
    }
    
} 

?>