package server;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.milagro.amcl.BLS461.*;
import org.apache.milagro.amcl.HASH512;
import org.apache.milagro.amcl.RAND;


import server.interfaces.ServerCryptoModule;


public class SoftwareServerCryptoModule implements ServerCryptoModule {

	private BIG secret;
	private final FP12 generator = org.apache.milagro.amcl.BLS461.PAIR.fexp(PAIR.ate(ECP2.generator(),ECP.generator()));
	private Random rand;
	private RAND rng = new RAND();
	
	
	public SoftwareServerCryptoModule(Random random) {
		this.rand = random;
		rng.seed(0, null); //TODO
	}


	public void setupServer(BIG secret){
		this.secret = secret;
	}


	@Override
	public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature) throws Exception {
		Signature sig = null;
		if("RSA".equals(publicKey.getAlgorithm())) {
			sig = Signature.getInstance("SHA256withRSA");
		} else {
			sig = Signature.getInstance("SHA256withECDSA");
		}
		sig.initVerify(publicKey);
		for(byte[] bytes: input) {
			sig.update(bytes);
		}
		return sig.verify(signature);
	}

	@Override
	public byte[] getBytes(int noOfBytes) {
		byte[] bytes = new byte[noOfBytes];
		rand.nextBytes(bytes);
		return bytes;
	}
	
	@Override
	public ECP hashToECPElement(byte[] input) {
		HASH512 h = new HASH512();
		h.process_array(input);
		byte[] bytes = h.hash();
		BIG big1 = BIG.fromBytes(bytes);
		return ECP.generator().mul(big1);
	}
	
/*	private BIG hashToBIG(byte[] input, String ssid) {
		HASH512 h = new HASH512();
		h.process_array(input);
		h.process_array(ssid.getBytes());
		byte[] bytes = h.hash();

		return BIG.fromBytes(bytes);
	}*/

	@Override
	public byte[] hash(List<byte[]> input) {
		HASH512 h = new HASH512();
		for(byte[] b: input) {
			h.process_array(b);
		}
		return h.hash();
	}

	@Override
	public byte[] constructNonce(String username, long salt) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(salt);
		List<byte[]> toHash = new ArrayList<>();
		toHash.add(buffer.array());
		toHash.add(username.getBytes());
		return hash(toHash);
	}

	public byte[] userSpecificKey(byte[] input, BIG sec)
	{
		List<byte[]> toHash = new ArrayList<>();
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(sec.hashCode());
		toHash.add(input);
		toHash.add(buffer.array());
		return hash(toHash);
	}

	@Override
	public BIG getRandomNumber() {
		return BIG.random(rng);
	}

	@Override
	public FP12 hashAndPair(byte[] input, ECP2 x, ECP com) {
		byte[] bytes = userSpecificKey(input,this.secret);
		BIG osk = BIG.fromBytes(bytes); //calculate osk, osk: F(uid, ki)
		FP12 y;
		if(com!=null)
			y = PAIR.fexp(PAIR.ate(x, com));    // com is not null, computing y2, which is necessary for Encryption
		y = PAIR.fexp(PAIR.ate(x,ECP.generator())); // com is null, computing y1, which is necessary for KeyPair
		return y;   //y1 or y2
	}
}
