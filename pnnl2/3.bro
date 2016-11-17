@load base/protocols/conn

event new_connection(c: connection ){
print c;
}

event connection_state_remove(c: connection)
    {
    print c;
    }
