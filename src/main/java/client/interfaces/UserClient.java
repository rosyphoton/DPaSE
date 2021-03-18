package client.interfaces;

import model.exceptions.UserCreationFailureException;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;

public interface UserClient {

    public long createUserAccount(String username, String password) throws UserCreationFailureException, RemoteException, NotBoundException;

    public long EncDecRequest(String username, String password) throws RemoteException, NotBoundException;

}