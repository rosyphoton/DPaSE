package model.exceptions;

public class UserCreationFailureException extends Exception{

	public UserCreationFailureException() {
	}

	public UserCreationFailureException(Exception e) {
		super(e);
	}

	public UserCreationFailureException(String string) {
		super(string);
	}

}