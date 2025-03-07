FromDevice(enp0s3,1) -> c :: Classifier(12/0800,-);        // IP packets

c[0]
	-> CheckIPHeader()
    -> DecIPTTL
    -> Discard;
c[1] -> Discard;