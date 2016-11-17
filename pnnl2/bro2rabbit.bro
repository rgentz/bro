const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro_for_rabbit2bro";
global msg_count = 0;

event bro_init()
	{
	Broker::enable();
	Broker::subscribe_to_prints("bro/print/");
	#Broker::listen(broker_port, "127.0.0.1");  #uncomment this to make bro the server
        Broker::connect("127.0.0.1", broker_port, 1sec);
	print "sending intitial fuck";
	Broker::send_print("bro/events/test", "fuck");
	}

event Broker::incoming_connection_established(peer_name: string)
	{
	print "Broker::incoming_connection_established", peer_name;
	}

event Broker::print_handler(msg: string)
	{
	++msg_count;
	print "got print message", msg;

	if ( msg_count == 3 )
		#terminate();

	print "sending back hello world";
	Broker::send_print("bro/events/test", "hello world");

	}


event Broker::incoming_connection_broken(peer_name: string)
        {
        print "Broker::incoming_connection_broken", peer_name;
        
	#terminate();
        }

