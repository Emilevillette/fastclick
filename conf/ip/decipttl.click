//FromDevice(eth0,1) -> c :: Classifier(12/0800,-);        // IP packets
FromDPDKDevice(0, MAXTHREADS 1, MODE none) -> c :: Classifier(12/0800,-);        // IP packets

c[0]
    -> EtherMirror()
    -> Strip(14)
    -> CheckIPHeader()
    -> DecIPTTL
    -> CheckIPHeader(CHECKSUM true)
    -> IPMirror()
    //-> Queue
    -> Unstrip(14)
    -> Discard;
    //-> ToDevice(eth0);
    //-> ToDPDKDevice(0, N_QUEUES 1);
c[1] -> Discard;
