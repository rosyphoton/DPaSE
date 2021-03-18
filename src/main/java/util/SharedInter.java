package util;

import model.OPRFResponse;
import org.apache.milagro.amcl.BLS461.ECP;
import org.apache.milagro.amcl.BLS461.ECP2;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public interface SharedInter extends Remote {
    public Boolean DTfinishRegistration(int serverid, String username, PublicKey publicKey, long salt) throws Exception, RemoteException;

    public OPRFResponse DTperformOPRF(int serverid, String ssid, String username, byte[] x_bt, byte[] com_bt) throws NoSuchAlgorithmException, Exception, RemoteException;

    public Boolean DTauthenticate(int serverid, String username, long salt, byte[] signature) throws Exception, RemoteException;
}
