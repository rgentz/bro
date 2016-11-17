const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;

global h: opaque of BrokerStore::Handle;
global expected_key_count = 4;
global key_count = 0;

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_events("bro/event/ready");
	BrokerComm::listen(broker_port, "10.4.32.100");
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	h = BrokerStore::create_master("mystore");
	BrokerStore::insert(h, BrokerComm::data("one"), BrokerComm::data(110));
	when ( local res = BrokerStore::size(h) )
		{
		print "master size", res;
		}
	timeout 10sec
		{ print "timeout"; }
		

	}

event ready(){
 print "Printing called remotely, next current datastorage";
 when ( local res = BrokerStore::size(h) )
                {
                print "master size", res;
                }
        timeout 10sec
                { print "timeout"; }

}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established", peer_name;
	}


