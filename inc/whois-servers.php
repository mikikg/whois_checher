<?php

//-------------------------------------------------------------
// Simple Whois checker
// Author: A. Markovic <mikikg@gmail.com>
//-------------------------------------------------------------

if (!defined('MyWhoisChecker')) die ('Direct script access forbidden!');

// For the full list of TLDs/Whois servers see http://www.iana.org/domains/root/db/
$whois_servers = array(
    'com' => 'whois.verisign-grs.com',
    'net' => 'whois.verisign-grs.net',
    'org' => 'whois.pir.org',
    'edu' => 'whois.educause.edu',
);

