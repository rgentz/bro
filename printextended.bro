
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef BrokerComm::endpoint_name = "listener";
global msg_count = 0;
global my_event: event(msg: string, c: count);
global my_event2: event();
global my_event3: event(msg: string);

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_prints("bro");
	BrokerComm::listen(broker_port, "10.4.32.100");
	BrokerComm::subscribe_to_events("bro/event");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established", peer_name;
	}

event BrokerComm::print_handler(msg: string)
	{
	++msg_count;
	print "got print message", msg;

##	if ( msg_count == 3 )
##		{		
##		terminate();
##
##		}
	}

event my_event(msg: string, c: count)
        {
        ++msg_count;
        print "got my_event", msg, c;
        }


event my_event2()
        {
        
        print "got my_event2";
        }


event my_event3(msg: string)
        {
        print "got my_event", msg;
        }

