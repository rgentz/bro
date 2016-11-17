
@load base/protocols/krb/

event bro_init(){
 print "startup";
}

event bro_done(){
 print "finished";
}



event krb_as_request(c: connection, msg: KRB::KDC_Request)
{
 print msg;
}

event krb_as_response(c: connection, msg: KRB::KDC_Response)
{
 print msg;
}
event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
{
 print msg;
}
event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
{
 print msg;
}
event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
{
print c;
}

event krb_ap_response(c: connection)
{
print c;
}

event krb_priv(c: connection, is_orig: bool)
{
print c;
}

event krb_safe(c: connection, is_orig: bool, msg: KRB::SAFE_Msg)
{
 print msg;
}
event krb_cred(c: connection, is_orig: bool, tickets: KRB::Ticket_Vector)
{
print c;
}

event krb_error(c: connection, msg: KRB::Error_Msg)
{
 print msg;
}
