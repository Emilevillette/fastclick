//FromDevice(eth0,1) -> c :: Classifier(12/0800,-);        // IP packets
FromDPDKDevice(0, MAXTHREADS 1, MODE none, VERBOSE 99) -> c :: Classifier(12/0800,-);        // IP packets

c[0]
    -> EtherMirror()
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM true, VERBOSE true)
    -> DecIPTTL
    -> CheckIPHeader(CHECKSUM true, VERBOSE true)
    -> IPMirror()
    //-> Queue
    -> Unstrip(14)
    -> Discard;
    //-> ToDevice(eth0);
    //-> ToDPDKDevice(0, N_QUEUES 1);
c[1] -> Discard;
