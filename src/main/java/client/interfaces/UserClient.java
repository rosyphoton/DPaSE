package client.interfaces;

import model.exceptions.UserCreationFailureException;

public interface UserClient {

    public long createUserAccount(String username, String password) throws UserCreationFailureException;

    public long EncDecRequest(String username, String password);

}