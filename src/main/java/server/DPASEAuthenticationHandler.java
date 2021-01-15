package server;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.milagro.amcl.BLS461.*;
import org.apache.milagro.amcl.BLS461.FP12;
import model.OPRFResponse;
import model.exceptions.ExistingUserException;
import model.exceptions.UserCreationFailureException;
import server.interfaces.AuthenticationHandler;
import server.interfaces.DPASEDatabase;
import server.interfaces.ServerCryptoModule;
import server.interfaces.Storage;

public class DPASEAuthenticationHandler extends AuthenticationHandler{

	private DPASEDatabase database;
	private List<DPASESP> servers;
	private ServerCryptoModule crypto;
	private static final long allowedTimeDiff = 10000;
	int id;

	public DPASEAuthenticationHandler(Storage database, int id, ServerCryptoModule crypto) throws Exception {
		super(database);
		if(database instanceof DPASEDatabase) {
			this.database = (DPASEDatabase) database;
		} else {
			throw new Exception("Not a valid database");
		}
		this.id = id;
		this.crypto = crypto;
/*		super.addIdentityProver(new IdentityProver(){
			//TODO remove test prover
			@Override
			public boolean isValid(IdentityProof proof) {
				return true;
			}
			
		});*/
	}

	public OPRFResponse performOPRF(String ssid, String username, ECP2 x, ECP com) {
		FP12 y = crypto.hashAndPair(username.getBytes(), x, com);   //calculate the value of y, which is necessary for the calculation of keypair
		OPRFResponse res = new OPRFResponse(y, ssid);   //ssid is transmitted into class OPRFResponse, res can call getSsid() to get ssid
		return res;
	}
	
/*	//TODO A server (or anyone) may add multiple partial signatures, is this problematic?
	public void addPartialServerSignature(String ssid, byte[] signature) {
		this.database.addPartialSignature(ssid, signature);
	}*/

	public Boolean finishRegistration(String username, PublicKey publicKey, long salt) throws Exception {
		if(this.database.hasUser(username)) {
			throw new ExistingUserException();
		}
		long currentTime = System.currentTimeMillis();
		if (salt > currentTime+allowedTimeDiff || salt < currentTime - allowedTimeDiff) {
			throw new UserCreationFailureException("Timestamp in request is either too new or too old");
		}

		this.database.addUser(username, publicKey, salt);
		return true;
	}


	public boolean authenticate(String username, long salt, byte[] signature) throws Exception {
		PublicKey userKey = this.database.getUserKey(username);
		if (userKey == null) {
			return false;
		}
		if (!checkSalt(username, salt)) {
			return false;
		}
		byte[] nonce = crypto.constructNonce(username, salt);
		List<byte[]> list = new ArrayList<>(1);
		list.add(nonce);
		list.add(username.getBytes());
		boolean valid = crypto.verifySignature(userKey, list, signature);
		database.setSalt(username, salt);
		return (valid );
	}


	private boolean checkSalt(String username, long salt) {
		long oldSalt = this.database.getLastSalt(username);
		if (salt < oldSalt) {
			// Someone is reusing salt
			return false;
		}
		long currentTime = System.currentTimeMillis();
		if (salt > currentTime+allowedTimeDiff || salt < currentTime - allowedTimeDiff) {
			// The salt is too far from the current time
			return false;
		}
		return true;
	}

}
