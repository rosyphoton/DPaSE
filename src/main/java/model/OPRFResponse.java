package model;

import org.apache.milagro.amcl.BLS461.FP12;

import java.io.Serializable;

public class OPRFResponse implements Serializable {

//	private FP12 y;
	private String ssid;
	private byte[] y_bt;

	public OPRFResponse(){
		
	}
	
	public OPRFResponse(byte[] y_bt, String ssid) {
//public OPRFResponse(FP12 y) {
		super();
//		this.y = FP12.fromBytes(y_bt);
		this.ssid = ssid;
		this.y_bt = y_bt;
	}

	public String getSsid() {
		return ssid;
	}

	public void setSsid(String ssid) {
		this.ssid = ssid;
	}

//	public void setY(FP12 y) {
//		this.y = y;
//	}

//	public FP12 getY() {
//		return y;
//	}

	public byte[] getY(){
		return y_bt;
	}

}
