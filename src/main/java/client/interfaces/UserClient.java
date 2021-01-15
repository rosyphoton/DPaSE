package client.interfaces;

import model.exceptions.UserCreationFailureException;

public interface UserClient {

    public void createUserAccount(String username, String password) throws UserCreationFailureException;

    public String EncDecRequest(String username, String password);

}