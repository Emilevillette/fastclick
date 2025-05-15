FromDPDKDevice(0, BURST 32, VERBOSE 99) -> c :: Classifier(12/0800, -);

c[0]
    -> EtherMirror()
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM true, VERBOSE true)
    -> DecIPTTL
    -> IPMirror()
    -> Unstrip(14)
    -> ToDPDKDevice(0, BLOCKING false, VERBOSE 99);

c[1]
    -> Discard;
