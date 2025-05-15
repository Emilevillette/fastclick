FromDPDKDevice(0, VERBOSE 99) -> c :: Classifier(12/0800, -);

c[0]
    -> EtherMirror()
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM true, VERBOSE true)
    -> d :: IPFilter(allow 0.0.0.0/5, allow 8.0.0.0/5, allow 16.0.0.0/5, allow 24.0.0.0/5, allow 32.0.0.0/5, allow 40.0.0.0/5, allow 48.0.0.0/5, allow 56.0.0.0/5, allow 64.0.0.0/5, allow 72.0.0.0/5, allow 80.0.0.0/5, allow 88.0.0.0/5, allow 96.0.0.0/5, allow 104.0.0.0/5, allow 112.0.0.0/5, allow 120.0.0.0/5, allow 128.0.0.0/5, allow 136.0.0.0/5, allow 144.0.0.0/5, allow 152.0.0.0/5, allow 160.0.0.0/5, allow 168.0.0.0/5, allow 176.0.0.0/5, allow 184.0.0.0/5, allow 192.0.0.0/5, allow 200.0.0.0/5, allow 208.0.0.0/5, allow 216.0.0.0/5, allow 224.0.0.0/5, allow 232.0.0.0/5, allow 240.0.0.0/5, allow 248.0.0.0/5, deny all);
    //-> d :: IPClassifier(0.0.0.0/2, 64.0.0.0/2, 128.0.0.0/2, 192.0.0.0/2, -);

d[0-31]
    -> DecIPTTL
    -> IPMirror()
    -> Unstrip(14)
    -> ToDPDKDevice(0, BLOCKING false, VERBOSE 99);

c[1], d[32]
    -> Discard;
