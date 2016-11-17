const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef BrokerComm::endpoint_name = "listener";
global msg_count = 0;
global h: opaque of BrokerStore::Handle;
global myvec: vector of string = {"alpha"};


event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_prints("bro/print/");
	BrokerComm::listen(broker_port, "10.4.32.100");
        h = BrokerStore::create_master("mystore");

	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established", peer_name;
	}

event BrokerComm::print_handler(msg: string)
	{
	++msg_count;
	print "got print message", msg;

	local test_string = "The quick brown fox jumps over the lazy dog.";
        local test_pattern = "/quick|lazy/";
    
        {
        local results = split_string(test_string, /fox/);
        print results[1];
        }


	myvec[0]=msg;
	BrokerStore::insert(h, BrokerComm::data("myvec"), BrokerComm::data(myvec));
	}
