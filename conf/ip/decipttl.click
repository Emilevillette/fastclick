FromDPDKDevice(0, VERBOSE 99)
    -> EtherMirror()
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM true, VERBOSE true)
    -> DecIPTTL
    //-> CheckIPHeader(CHECKSUM true, VERBOSE true)
    -> IPMirror()
    //-> Queue
    -> Unstrip(14)
    -> ToDPDKDevice(0, BLOCKING true, VERBOSE 99);
