/*
package eu.olympus.server.interfaces;

import eu.olympus.model.Attribute;

import java.util.Map;

*/
/**
 * Interface for storage used by a "traditional" password
 * verification scheme implementation
 * 
 *//*

public interface UserPasswordDatabase extends Storage {

	*/
/**
	 * Add a user to the database.
	 * @param username Username of the user.
	 * @param salt The salt generated during enrolment
	 * @param password The hashed password
	 *//*

	public void addUser(String username, String salt, String password);
	
	*/
/**
	 * Get the password of a stored user
	 * @param username The username of the password to get
	 * @return The stored password
	 *//*

	public String getPassword(String username);
	
	*/
/**
	 * Get the salt of a stored user
	 * @param username The username of the salt to get
	 * @return The stored salt
	 *//*

	public String getSalt(String username);
	
	public Map<String, Attribute> getAttributes(String username);

}
*/
