<?php

//-------------------------------------------------------------
// Simple Whois checker
// Author: A. Markovic <mikikg@gmail.com>
//
// Class file for WHOIS checker
//-------------------------------------------------------------

if (!defined('MyWhoisChecker')) die ('Direct script access forbidden!');

class MyWhoisChecker
{

    //private vars
    private $NL;
    private $domain_name = '';
    private $domain_tld = '';
    private $is_valid_string = false;
    private $is_registred_domain = false;
    private $error_code = 0;
    private $error_string = '';
    private $server_list = array();
    private $whois_response = '';

    //Constructor
    public function __construct()
    {

        //Get current directory of this script
        $current_path = dirname(__FILE__);

        //Check existence of whois list file
        $whois_list_file = $current_path . "/whois-servers.php";
        if (is_file($whois_list_file)) {
            include_once($whois_list_file);
        } else {
            //file not found
            die ("FATAL ERROR: Failed opening required file 'whois-servers.php'\n");
        }

        //check does we run this script trough CLI or WEB SERVER
        php_sapi_name() == 'cli' ? $this->NL = "\n" : $this->NL = '<br />';

        //get list of whois servers from file
        include_once($whois_list_file);
        $this->server_list = $whois_servers;
    }

    //Filter and assign to vars domain and TLD
    public function set_input($domain)
    {

        //by default is false
        $this->is_valid_string = false;

        //basic input filtering
        $domain = substr(strtolower(trim($domain)), 0, 100); //max 100 chars allowed, lower case

        //remove HTTP:// HTTPS:// WWW. SPACES
        $domain = str_ireplace(array('http://', 'https://', 'www.', ' '), '', $domain);

        //return only TLD and Domain from string
        $parts = explode('.', $domain);
        $tld = end($parts);
        $name = prev($parts);

        //if not empty assign values
        if (!empty($tld) && !empty($name)) {
            $this->domain_name = $name;
            $this->domain_tld = $tld;
        }

        //check now for ICANN rules
        if (!preg_match("/^([-a-z0-9]{1,63})\.([a-z\.]{2,24})$/i", $this->domain_name . '.' . $this->domain_tld)) {
            //not valid!
            return;
        }

        //Does our system support this TLD?
        if (!isset($this->server_list[$this->domain_tld])) {
            $this->error_code = '1';
            $this->error_string = 'This TLD is not currently supported for query.';
            return;
        }

        //looks good
        $this->is_valid_string = true;

    }

    //Function to query WHOIS server based on TLD
    public function query_whois_server()
    {

        $this->is_registred_domain = false;
        $this->whois_response = "\n";

        //make socket connection to specified whois server for requested TLD
        $fp = @fsockopen($this->server_list[$this->domain_tld], $port = 43, $errno, $errstr, $timeout = 10) or die("Socket Error " . $errno . " - " . $errstr);
        fputs($fp, $this->get_valid_domain_name() . "\r\n");
        while (!feof($fp)) { //read until end of stream/file
            $this->whois_response .= fgets($fp);
        }
        fclose($fp);

        //if we found strings 'Domain Name:' and 'Name Server' in response, then domain is registered
        if (stripos($this->whois_response, 'Domain Name:') !== false && stripos($this->whois_response, 'Name Server') !== false) {
            //domain is registered!
            $this->is_registred_domain = true;
        }

    }

    //helper funcs
    public function get_valid_domain_name()
    {
        return $this->domain_name . '.' . $this->domain_tld;
    }

    //helper
    public function is_valid_string()
    {
        return $this->is_valid_string;
    }

    //helper
    public function get_error_string()
    {
        return $this->error_string;
    }

    //helper
    public function is_registred_domain()
    {
        return $this->is_registred_domain;
    }

    //helper
    public function get_whois_response()
    {
        return $this->whois_response;
    }

    //helper
    public function get_tld_list()
    {
        return implode(', ', array_keys($this->server_list));
    }

}

