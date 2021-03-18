package server;

import model.OPRFResponse;
import org.apache.milagro.amcl.BLS461.ECP;
import org.apache.milagro.amcl.BLS461.ECP2;
import util.SharedInter;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;

public class DPASESPTool extends UnicastRemoteObject implements SharedInter{
    private List<? extends DPASESP> servers;

    public DPASESPTool(List<? extends DPASESP> servers) throws RemoteException{
        super();
        this.servers = servers;
    }

    @Override
    public OPRFResponse DTperformOPRF(int serverid, String ssid, String username, byte[] x_bt, byte[] com_bt) throws NoSuchAlgorithmException, Exception, RemoteException {
        ECP2 x = ECP2.fromBytes(x_bt);
        ECP com;
        if (com_bt == null){
            com = null;
        }
        else{
            com = ECP.fromBytes(com_bt);
        }
        return servers.get(serverid).performOPRF(ssid, username, x, com);
    }

    @Override
    public Boolean DTfinishRegistration(int serverid, String username, PublicKey publicKey, long salt) throws Exception, RemoteException {
        return servers.get(serverid).finishRegistration(username, publicKey, salt);
    }

    @Override
    public Boolean DTauthenticate(int serverid, String username, long salt, byte[] signature) throws Exception {
        return servers.get(serverid).authenticate(username, salt, signature);
    }
}
