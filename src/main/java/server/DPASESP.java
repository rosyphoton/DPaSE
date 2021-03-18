package server;
import java.io.Serializable;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.apache.milagro.amcl.BLS461.*;
import model.OPRFResponse;
import model.exceptions.UserCreationFailureException;
import server.interfaces.ServerCryptoModule;
import server.interfaces.Storage;
import util.SharedInter;


public class DPASESP {

	private DPASEAuthenticationHandler authenticationHandler;
	private ServerCryptoModule cryptoModule;


	public DPASESP(Storage database, int id) throws Exception{
		if (database != null) {
			cryptoModule = new SoftwareServerCryptoModule(new SecureRandom());
			authenticationHandler = new DPASEAuthenticationHandler(database, id, cryptoModule);
		}
	}


	public void setup(BIG secret) {
		try {
			cryptoModule.setupServer(secret);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	public OPRFResponse performOPRF(String ssid, String username, ECP2 x, ECP com) throws NoSuchAlgorithmException{
		return authenticationHandler.performOPRF(ssid, username, x, com);
	}

	public Boolean finishRegistration(String username, PublicKey publicKey, long salt) throws Exception{
		return authenticationHandler.finishRegistration(username, publicKey, salt);
	}

	public Boolean authenticate(String username, long salt, byte[] signature) throws Exception {
		boolean authenticated = authenticationHandler.authenticate(username, salt, signature);
		if(authenticated) {
			try{
				return true;
			} catch(Exception e) {
				e.printStackTrace();
				return false;
			}
		}
		return false;
	}

}
