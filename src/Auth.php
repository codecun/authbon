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
    private $_error            = null;

    /*==============================================================================================================================
    * Autentificacion con el Objeto Header
    ==============================================================================================================================*/
    public function login($user, $password, $model)
    {
        // Check whether the account has been banned.
        if ($model->banned) {
            $this->_error = "Check whether the account has been banned.";
            return false;
        }

        // Check whether the username, email, or password doesn't exist.
        if ($model == false) {
            $this->_error = "Check whether the username, email, or password doesn't exist.";
            return false;
        }

        // Check whether the account has been soft deleted. The >= 1 check ensures
        // this will still work if the deleted field is a UNIX timestamp.
        if ($model->deleted >= 1) {
            $this->_error = "Check whether the account has been soft deleted.";
            return false;
        }

        // Try password
        if (! $this->check_password($password, $model->password_hash)) {
            $this->_error = "Incorrect Password";
            return false;
        }

        // Check whether the user needs to reset their password.
        if ($model->force_password_reset == 1) {
            $this->_error = "Check whether the user needs to reset their password.";
            return false;
        }

        return true;
    }

    public function getError()
    {
        return $this->_error;
    }

    public function check_password($password, $hash)
    {
        // Load the password hash library
        $this->_cpass = new CPass(-1, false);

        // Try password
        return $this->_cpass->CheckPassword($password, $hash);
    }
    
} 

?>