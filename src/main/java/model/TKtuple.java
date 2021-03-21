package model;

import java.security.KeyPair;

public class TKtuple {
    public final long sum_time;
    public final KeyPair upk;

    public TKtuple(long sum_time, KeyPair upk) {
        this.sum_time = sum_time;
        this.upk = upk;
    }

    public long getTime(){
        return sum_time;
    }

    public KeyPair getUkp(){
        return upk;
    }
}
