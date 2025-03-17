FromDevice(eth0,1) -> c :: Classifier(12/0800,-);        // IP packets
//FromDPDKDevice(0) -> c :: Classifier(12/0800,-);        // IP packets

c[0]
    -> EtherMirror()
    -> Strip(14)
    -> CheckIPHeader()
    -> DecIPTTL
    -> CheckIPHeader(CHECKSUM true)
    -> IPMirror()
    -> Queue
    -> Unstrip(14)
    -> ToDevice(eth0);
    //-> ToDPDKDevice(1);
c[1] -> Discard;
