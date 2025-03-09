FromDevice(eth0,1) -> c :: Classifier(12/0800,-);        // IP packets

c[0]
    -> Strip(14)
	-> CheckIPHeader()
    -> DecIPTTL
    -> Discard;
c[1] -> Discard;