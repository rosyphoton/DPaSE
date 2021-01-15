package client.interfaces;

import util.CommonCrypto;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import org.apache.milagro.amcl.BLS461.BIG;
import org.apache.milagro.amcl.BLS461.ECP2;
import org.apache.milagro.amcl.BLS461.ECP;

public interface ClientCryptoModule extends CommonCrypto {

    public KeyPair generateKeysFromBytes(byte[] privateBytes) throws Exception;

    public byte[] sign(PrivateKey privateKey, List<byte[]> message) throws Exception;

    public ECP2 hashAndMultiply(BIG r, byte[] password);

    public ECP hashToECPElement(byte[] block);

    public byte[] HPRG(byte[] seed, int length);

}
