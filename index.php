<?php

//-------------------------------------------------------------
// Simple Whois checker
//
// Author: A. Markovic <mikikg@gmail.com>
//-------------------------------------------------------------

define("MyWhoisChecker", true);

//Check existence of engine class file
$class_file = dirname(__FILE__) . "/inc/engine.class.php";
if (is_file($class_file)) {
    //Include engine class file
    include_once($class_file);
} else {
    //class not found
    die ("FATAL ERROR: Failed opening required file '$class_file'\n");
}

//Check existence of template file
$html_template = '';
$tmpl_file = dirname(__FILE__) . "/tmpl/template.html";
if (is_file($tmpl_file)) {
    //Load file content
    $html_template = file_get_contents($tmpl_file);
} else {
    //file not found
    die ("FATAL ERROR: Failed opening required file '$tmpl_file'\n");
}

//Init engine object
$my_obj = new MyWhoisChecker;

//Assign some template defaults
$html_template = str_replace('##supported_tlds##', $my_obj->get_tld_list(), $html_template);

//actions
if (isset($_GET['domain']) && !empty($_GET['domain'])) {

    //set and filter input string
    $my_obj->set_input($_GET['domain']);

    //is valid string for query
    $valid = $my_obj->is_valid_string();

    if ($valid) {
        //exec WHOIS query
        $my_obj->query_whois_server();

        //parse template
        $html_template = str_replace(
            '##response_html##',
            sprintf("Domain '%s' is %s\n\n", $my_obj->get_valid_domain_name(), $my_obj->is_registred_domain() ? 'REGISTERED' : 'FREE'),
            $html_template);

        $html_template = str_replace('##response2_html##', $my_obj->get_whois_response(), $html_template);

    } else {
        $html_template = str_replace('##response_html##', 'Invalid query string', $html_template);
        $html_template = str_replace('##response2_html##', '', $html_template);

    }

} else {
    $html_template = str_replace(array('##response_html##', '##response2_html##'), '', $html_template);
}

echo $html_template;

